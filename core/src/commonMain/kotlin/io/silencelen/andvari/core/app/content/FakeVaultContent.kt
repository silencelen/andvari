package io.silencelen.andvari.core.app.content

import io.silencelen.andvari.core.app.AttachmentLimitsView
import io.silencelen.andvari.core.app.AttachmentRules
import io.silencelen.andvari.core.client.AttachmentRef
import io.silencelen.andvari.core.client.CardData
import io.silencelen.andvari.core.client.CsvImport
import io.silencelen.andvari.core.model.wire.SyncItem
import io.silencelen.andvari.core.client.DecryptedItemVersion
import io.silencelen.andvari.core.client.DeletedItemView
import io.silencelen.andvari.core.client.ItemDoc
import io.silencelen.andvari.core.client.LoginData
import io.silencelen.andvari.core.client.VaultItem
import io.silencelen.andvari.core.client.items.HeldRescue
import io.silencelen.andvari.core.client.items.HeldVaultView
import io.silencelen.andvari.core.client.items.ItemCodec
import io.silencelen.andvari.core.client.items.ItemFailure
import io.silencelen.andvari.core.client.items.MovePlan
import io.silencelen.andvari.core.client.items.MovedAttachment
import io.silencelen.andvari.core.client.items.ItemNotice
import io.silencelen.andvari.core.client.items.ItemRefusal
import io.silencelen.andvari.core.client.items.ItemResult
import io.silencelen.andvari.core.client.items.NewAttachment
import io.silencelen.andvari.core.client.items.SavedItem
import io.silencelen.andvari.core.client.items.SyncReport
import io.silencelen.andvari.core.client.items.VaultAccess
import io.silencelen.andvari.core.client.items.VaultStanding
import io.silencelen.andvari.core.client.items.VaultView
import io.silencelen.andvari.core.client.items.Written
import io.silencelen.andvari.core.client.net.NoAnswerKind
import io.silencelen.andvari.core.crypto.Attachments
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.CryptoProvider
import io.silencelen.andvari.core.crypto.Hibp
import io.silencelen.andvari.core.crypto.KeysGoneException
import io.silencelen.andvari.core.crypto.createCryptoProvider

/**
 * [VaultContent] in memory, for previews and UI tests: the same rules as [EngineVaultContent] (one controller decides
 * both), over a pretend server a test can script. It starts with a personal vault ([PERSONAL_VAULT_ID]) and no items.
 *
 * Scripting: [seedLogin], [seedNote], [seedCard] and [addSharedVault] fill it; [setOffline] cuts the network (saves
 * are queued, as on a durable cache, and a later sync sends them); [stopServer] is a forked pin (readable, nothing can
 * be saved); [failNextWith] makes the next operation fail as the engine would; [rollbackNextSync] makes the next sync
 * meet a server that went backwards; [raiseNotice] adds a notice. After scripting, the state shows it at once.
 */
class FakeVaultContent private constructor(
    private val fake: FakeContentSource,
    private val keeping: ContentKeeping?,
    /** What a lock cut short, held across this fake's unlocks ([reopened]) as the app's process holds the real one's. */
    private val held: UnsavedAtLock,
    private val controller: ContentController = ContentController(fake, fake.crypto, fake, keeping, held),
) : VaultContent by controller {
    constructor() : this(FakeContentSource(createCryptoProvider()), null, UnsavedAtLock())

    /**
     * The fake over [crypto] in place of the platform's: an app's JVM tests hand it a provider of their own (the
     * platform's needs its native library). Everything else is as the no-argument constructor makes it.
     */
    constructor(crypto: CryptoProvider) : this(FakeContentSource(crypto), null, UnsavedAtLock())

    /**
     * The next unlock's content, after this one [close]d on a lock: a new instance, as the engine's is, over the same
     * pretend server and the same device copy, so everything seeded, saved, queued or deleted is still there; and what
     * a lock cut short here is said there once ([ContentState.notice] of kind [ContentNoticeKind.LOCK]), as the real one
     * says it. The editor's open files, an open trash, history or import do not carry over (they do not on the engine).
     */
    fun reopened(): FakeVaultContent = FakeVaultContent(fake, keeping, held)

    /**
     * The server ended the session (design §4.4: a refused refresh, a revoked session): this copy stays as it is, with
     * every change still waiting to be sent, read-only (nothing is sent or written) until [signedInAgain]. Not a fork:
     * the next unlock's content ([reopened]) stays read-only with the same queue, and signing in again opens the same
     * copy writable, whose next sync sends what waited, as the engine's copy does.
     */
    fun endedByServer() {
        fake.endedByServer = true
        controller.publish()
    }

    /** Signed in again to the same account at the same server, after [endedByServer]: the same copy, writable, as [reopened]. */
    fun signedInAgain(): FakeVaultContent {
        fake.endedByServer = false
        return reopened()
    }

    // ---- the notices of a lock and of a misbehaving server, for a screen test (item 2's kinds) ----

    /**
     * What a lock cut short ([LockCut]), to be said at the next unlock (or at once on this content's next state while it
     * is open): [name] the item, file or (COPY) source vault, [target] the vault written into, [done] of [total] for COPY
     * and IMPORT.
     */
    fun raiseLockCut(kind: LockCutKind, name: String, target: String, done: Int, total: Int) {
        val notes = keeping?.unsaved ?: held
        when (kind) {
            LockCutKind.SAVE -> notes.save(name)
            LockCutKind.CSV_IMPORT -> notes.import(done, total - done)
            else -> notes.cut(kind, name, target, done, total)
        }
        controller.publish()
    }

    /** "The server said your personal vault was taken away… kept it" ([ContentCopy.PERSONAL_KEPT]), as a vault notice. */
    fun raisePersonalKept() = raiseNotice(PERSONAL_VAULT_ID, "Personal", ItemNotice.PERSONAL_KEPT, 0)

    /** The next trash read meets a list that does not come to its end ([ContentCopy.TRASH_LIST_INCOMPLETE]). */
    fun failNextTrashRead() = failNextWith(ItemFailure.Corrupt(io.silencelen.andvari.core.client.items.ItemTransport.TRASH_INCOMPLETE))

    /**
     * From now on (true) the pretend server answers a restore from the trash and a delete for good as done and stores
     * nothing: the next opening of the trash says so ([ContentNoticeKind.NOT_DONE_ON_SERVER]).
     */
    fun trashActionsStoreNothing(on: Boolean) {
        fake.trashActionsStoreNothing = on
    }

    /**
     * The fake with the extensions' save queue [saveQueue], the twin of [ContentCapture.queue] for the screens' tests:
     * the key is published there at the first sync, a capture queued there (by [ContentCapture.queue], or an extension's
     * `SaveQueue.enqueue`) is read at the next [syncQuietly], [refresh] or [readSaveQueue], and saved or listed under the
     * real rules ([ContentState.appliedSaves], [ContentState.pendingSaves]). Its account is a pretend one, and the
     * policy allows keeping data on this device. Everything else is as the one-argument constructor makes it.
     */
    constructor(crypto: CryptoProvider, saveQueue: io.silencelen.andvari.core.app.SaveQueueStore) :
        this(FakeContentSource(crypto).also { it.keepsData = true }, saveQueue)

    private constructor(fake: FakeContentSource, saveQueue: io.silencelen.andvari.core.app.SaveQueueStore) :
        this(fake, fake.keeping(saveQueue), UnsavedAtLock())

    /** What one file, and one item's files, may come to (the server's policy, as [AttachmentRules.limits] holds it). */
    fun setAttachmentLimits(perFileBytes: Long, perItemBytes: Long) {
        fake.limits = AttachmentRules.limits(perFileBytes, perItemBytes)
    }

    /** A file on [itemId], uploaded and listed. Answers its id. */
    fun seedAttachment(itemId: String, name: String, bytes: ByteArray): String {
        val item = fake.live.getValue(itemId)
        val key = fake.crypto.randomBytes(32)
        val enc = Attachments.encrypt(fake.crypto, key, bytes)
        val id = fake.freshId()
        fake.blobs[id] = item.vaultId to (enc.header + enc.ciphertext)
        fake.live[itemId] = item.copy(doc = item.doc.copy(attachments = item.doc.attachments + AttachmentRef(id, name, bytes.size.toLong(), Bytes.toB64(key))))
        key.fill(0)
        controller.publish()
        return id
    }

    /**
     * A login deleted [daysAgo] days ago, in the server's trash. Answers its id. With [notReadYet] the device never held
     * it and the trash's opening did not read it: its row has no name ([io.silencelen.andvari.core.app.TrashItemView.notReadYet])
     * until a restore reads it ([trashDocReads] counts those reads).
     */
    fun seedDeleted(vaultId: String, name: String, username: String, daysAgo: Int, notReadYet: Boolean = false): String {
        val id = fake.freshId()
        fake.deleted[id] = DeletedItemView(id, vaultId, fake.nowMs - daysAgo * 86_400_000L, ItemDoc(type = "login", name = name, login = LoginData(username = username)))
        if (notReadYet) fake.notReadYet += id
        return id
    }

    /** How many trash rows were read one at a time, for a restore of a row the trash's opening had not read. */
    val trashDocReads: Int get() = fake.trashDocReads

    /**
     * The shared vault [vaultId] left this account for a verified [reason] (`removed`, `left`, `deleted`, `purged`):
     * its items move to the holding area for 30 days, readable here while [readable] (its key still offered).
     */
    fun holdVault(vaultId: String, reason: String, readable: Boolean) {
        val v = fake.vaults.remove(vaultId) ?: return
        val items = fake.live.values.filter { it.vaultId == vaultId }
        items.forEach { fake.live.remove(it.itemId) }
        // As the engine: what waited to be sent into the vault leaves the queue and is parked with the held copy.
        val parked = fake.queue.filter { it.vaultId == vaultId }
        fake.queue.removeAll { it.vaultId == vaultId }
        fake.held[vaultId] = FakeContentSource.Held(v.name, reason, items, fake.nowMs + 30L * 86_400_000L, readable, owned = v.role == VaultAccess.ROLE_OWNER, parked = parked)
        controller.publish()
    }

    /**
     * The items of [vaultId] with a change this device made that has not reached the pretend server, as the engine's
     * `waitingChanges` names them: queued while the vault is open, or parked with its held copy once it left.
     */
    fun waitingChanges(vaultId: String): Set<String> = fake.waitingChanges(vaultId)

    /**
     * A shared vault this account deleted [daysAgo] days ago, in its 7-day grace, on the owner's "Recently deleted"
     * list. With [verified] false the server lists it but this device's log does not show the deletion: the content
     * leaves it out. Answers its id.
     */
    fun seedDeletedVault(name: String, daysAgo: Int, verified: Boolean = true, dayServed: Boolean = true): String {
        val id = fake.freshId()
        val at = fake.nowMs - daysAgo * 86_400_000L
        // [dayServed] false: a server that serves no end of the grace (the row then carries no day).
        fake.deletedVaultList += io.silencelen.andvari.core.client.items.DeletedVault(id, name, at, if (dayServed) at + 7L * 86_400_000L else 0L, "AAAAAAAAAAAAAAAAAAAAAA==", verified)
        return id
    }

    /** [password] is in the pretend breach corpus: a breach check finds it. */
    fun addBreachedPassword(password: String) {
        fake.breached += password
    }

    /** Files the pretend server holds, by id. */
    val uploadedFiles: Set<String> get() = fake.blobs.keys.toSet()

    /** Items in the pretend server's trash, by id. */
    val trashedItems: Set<String> get() = fake.deleted.keys.toSet()

    /** The pretend clock (unix milliseconds); one-time codes and dates read it. */
    var nowMs: Long
        get() = fake.nowMs
        set(value) {
            fake.nowMs = value
        }

    /**
     * The uses the content recorded for the session to send (spec 02 §8.2), item ids in order: a login or card released
     * to a fill, a secret revealed or copied, each item at most once a minute of [nowMs].
     */
    val recordedUses: List<String> get() = fake.uses.toList()

    /** When each of [recordedUses] was recorded as used (Unix milliseconds), in the same order. */
    val recordedUseTimes: List<Long> get() = fake.useTimes.toList()

    /** How many syncs reached the pretend server. */
    val syncCount: Int get() = fake.syncCount

    fun seedLogin(vaultId: String, name: String, username: String, password: String, uri: String): String =
        seed(vaultId, ItemDoc(type = "login", name = name, login = LoginData(username = username, password = password, uris = listOfNotNull(uri.ifEmpty { null }))))

    fun seedNote(vaultId: String, name: String, text: String): String = seed(vaultId, ItemDoc(type = "note", name = name, notes = text))

    fun seedCard(vaultId: String, name: String, number: String, expMonth: String, expYear: String): String =
        seed(vaultId, ItemDoc(type = "card", name = name, card = CardData(number = number, expMonth = expMonth, expYear = expYear)))

    /** Any item, as stored. */
    fun seed(vaultId: String, doc: ItemDoc): String {
        val id = fake.freshId()
        fake.live[id] = VaultItem(id, vaultId, 1, fake.nowMs, doc)
        controller.publish()
        return id
    }

    /** A shared vault this account can read, with its role and standing (design §3.9). */
    fun addSharedVault(vaultId: String, name: String, role: String, standing: VaultStanding) {
        fake.vaults[vaultId] = FakeContentSource.Vault(name, personal = false, role = role, standing = standing)
        controller.publish()
    }

    /** The account has no personal vault (design §5.3): a new item needs a chosen destination. */
    fun dropPersonalVault() {
        fake.vaults.remove(PERSONAL_VAULT_ID)
        fake.personal = null
        controller.publish()
    }

    /** No answer from the server from now on (true) or again (false). Saves are queued while it lasts. */
    fun setOffline(offline: Boolean) {
        fake.offline = offline
        controller.publish()
    }

    /** The server's card chain forked on this device (design §4.4): for good. */
    fun stopServer() {
        fake.forked = true
        controller.publish()
    }

    /**
     * This copy is being removed for the server's policy (as the engine while the policy's run is under way): a change
     * the person makes is refused with [ContentCopy.COPY_BEING_REMOVED], and nothing is sent. [on] false ends it.
     */
    fun removingForPolicy(on: Boolean = true) {
        fake.removingForPolicy = on
        controller.publish()
    }

    /** The next operation that would reach the server answers [failure] instead. */
    fun failNextWith(failure: ItemFailure) {
        fake.nextFailure = failure
    }

    /** The next sync meets a server that answered with an older state: nothing is applied, and a notice says so. */
    fun rollbackNextSync() {
        fake.rollbackNext = true
    }

    fun raiseNotice(vaultId: String, vaultName: String, kind: String, count: Int) {
        fake.noticeList.add(ItemNotice(fake.freshId(), vaultId, vaultName, kind, count.takeIf { it > 0 }))
        controller.publish()
    }

    /** What the pretend server holds of [itemId] (null when it holds nothing, or the item was deleted there). */
    fun serverDoc(itemId: String): ItemDoc? = fake.live[itemId]?.doc

    // ---- the account's own use and limits (spec 03 §14.4) ----

    /**
     * The use and limits the pretend server serves this account on every sync, as `GET /sync`'s `quota` (spec 03
     * §14.4); null (how the fake starts) serves none, as an older server: every check is then UNKNOWN and Settings'
     * [ContentState.storage] is null. A meter with a negative number is "none that can be meters": unknown too.
     */
    fun setQuota(quota: io.silencelen.andvari.core.model.wire.QuotaUse?) {
        fake.quotaUse = quota
        controller.publish()
    }

    /**
     * The boundaries in one call: the account has used 1000 bytes, 10 items, 1 owned shared vault and 2 open links, and
     * its limits leave exactly [bytesLeft], [itemsLeft] and [sharedVaultsLeft] (open links: 18). A copy of exactly what
     * is left fits ([SpaceVerdict.ROOM]); one more of any is [SpaceVerdict.NOT_ENOUGH] on that meter. Read what a check
     * asks for in [lastSpaceAsked], then set the room around it.
     */
    fun setRoomLeft(bytesLeft: Long, itemsLeft: Long, sharedVaultsLeft: Long) {
        fun m(used: Long, left: Long) = io.silencelen.andvari.core.model.wire.QuotaMeter(used, used + left)
        setQuota(io.silencelen.andvari.core.model.wire.QuotaUse(m(1000, bytesLeft), m(10, itemsLeft), m(1, sharedVaultsLeft), m(2, 18)))
    }

    /** What the last check before a large copy asked room for (null before any): bytes, items, a new vault, declared bytes. */
    val lastSpaceAsked: io.silencelen.andvari.core.client.items.CopySize? get() = fake.lastSpaceAsked

    /** How many checks before a large copy reached the pretend server (each is a sync). */
    val spaceChecks: Int get() = fake.spaceChecks

    /** How many times the controller read the vaults: a list's state reads them a fixed number of times, whatever its length. */
    val vaultReads: Int get() = fake.vaultReads

    /** [itemId]'s last change is [atMs] (the order of "recently updated"); nothing else about it changes. */
    fun setUpdatedAt(itemId: String, atMs: Long) {
        val it = fake.live[itemId] ?: return
        fake.live[itemId] = VaultItem(it.itemId, it.vaultId, it.rev, atMs, it.doc)
        controller.publish()
    }

    /**
     * A file on [itemId] whose document DECLARES [declaredBytes], as another member of a shared vault can write it:
     * the pretend server holds only a few real bytes. A copy of it is short only on declared sizes
     * when the stated size is what passes the limit ([SpaceVerdict.NOT_ENOUGH_ON_DECLARED_SIZES]). Answers the file's id.
     */
    fun seedDeclaredFile(itemId: String, name: String, declaredBytes: Long): String {
        val id = seedAttachment(itemId, name, byteArrayOf(1, 2, 3))
        val item = fake.live.getValue(itemId)
        fake.live[itemId] = item.copy(doc = item.doc.copy(attachments = item.doc.attachments.map { if (it.id == id) it.copy(size = declaredBytes) else it }))
        controller.publish()
        return id
    }

    companion object {
        const val PERSONAL_VAULT_ID = "00000000-0000-4000-8000-000000000001"
    }
}

/** The pretend item plane behind [FakeVaultContent]: the engine's answers, without crypto or a network. */
internal class FakeContentSource(val crypto: CryptoProvider) : ContentSource, ContentHost {
    override fun wallMs(): Long = nowMs
    override fun attachmentLimits(): AttachmentLimitsView = limits
    override fun origin(): String = "https://vault.example.com"
    override fun userId(): String = "00000000-0000-4000-8000-0000000000ff"
    override fun accountId(): String = "0123456789abcdef0123456789abcdef"
    override fun backupKdfParams(): io.silencelen.andvari.core.crypto.KdfParams? = null

    /** The fake keeps the extensions' save queue: the policy allows keeping data on this device. */
    var keepsData = false

    override fun offlineCacheAllowed(): Boolean = keepsData

    /** The uses the content recorded ([ContentHost.recordUse]), item ids in order. */
    val uses = ArrayList<String>()
    val useTimes = ArrayList<Long>()

    override fun recordUse(itemId: String, atMs: Long) {
        uses += itemId
        useTimes += atMs
    }

    /**
     * Kept records in memory over the save queue [queue], for a pretend account of [userId] (its keys fresh, its
     * personal vault [FakeVaultContent.PERSONAL_VAULT_ID]): what the extensions seal to it, the content opens.
     */
    fun keeping(queue: io.silencelen.andvari.core.app.SaveQueueStore): ContentKeeping {
        val seed = crypto.randomBytes(32)
        val identity = crypto.boxKeypairFromSeed(seed)
        val signing = crypto.signKeypairFromSeed(seed)
        seed.fill(0)
        val genesis = io.silencelen.andvari.core.trust.VerifiedGenesis(
            io.silencelen.andvari.core.trust.GenesisFields(userId(), Bytes.toB64(identity.publicKey), "fake-instance", FakeVaultContent.PERSONAL_VAULT_ID, 0),
            "00".repeat(32),
        )
        val account = io.silencelen.andvari.core.client.onboard.OpenedAccount(
            userId(), crypto.randomBytes(32), identity, signing, genesis, FakeVaultContent.PERSONAL_VAULT_ID, crypto.randomBytes(32),
        )
        return ContentKeeping(
            account, io.silencelen.andvari.core.app.InMemoryFillSnapshots(), io.silencelen.andvari.core.app.InMemoryFillSnapshots(),
            io.silencelen.andvari.core.app.InMemoryBlobs(), io.silencelen.andvari.core.app.InMemoryFillSnapshots(), queue,
        )
    }

    class Vault(var name: String, val personal: Boolean, val role: String, val standing: VaultStanding)

    /**
     * A vault in the holding area. [parked]: the changes this device made in it that had not reached the server when it
     * left, in order, parked with the held copy as the engine parks them (never sent, never dropped by the leaving).
     */
    class Held(
        val name: String, val reason: String, val items: List<VaultItem>, val expungeAt: Long, val readable: Boolean, val owned: Boolean = false,
        val parked: List<Queued> = emptyList(),
    )

    val held = LinkedHashMap<String, Held>()
    private val bulkPlans = HashMap<String, MovePlan>()

    /** One queued write: a put of [doc], or a delete when it is null. */
    class Queued(val itemId: String, val vaultId: String, val doc: ItemDoc?)

    var limits: AttachmentLimitsView = AttachmentRules.limits(null, null)
    val blobs = HashMap<String, Pair<String, ByteArray>>()
    val versions = HashMap<String, MutableList<DecryptedItemVersion>>()
    val deleted = LinkedHashMap<String, DeletedItemView>()
    var nowMs = 1_800_000_000_000L
    var personal: String? = FakeVaultContent.PERSONAL_VAULT_ID
    val vaults = LinkedHashMap<String, Vault>().also { it[FakeVaultContent.PERSONAL_VAULT_ID] = Vault("Personal", true, VaultAccess.ROLE_OWNER, VaultStanding.VERIFIED) }
    val live = LinkedHashMap<String, VaultItem>()
    val queue = ArrayList<Queued>()
    val noticeList = ArrayList<ItemNotice>()
    var offline = false
    /** The server's card chain forked ([FakeVaultContent.stopServer]): for good. */
    var forked = false

    /** The server ended the session ([FakeVaultContent.endedByServer]) until a sign-in again: read-only meanwhile. */
    var endedByServer = false

    /** The copy is being removed for the server's policy ([FakeVaultContent.removingForPolicy]): nothing new is taken in. */
    var removingForPolicy = false

    override fun removingForPolicy(): Boolean = removingForPolicy

    /** Nothing is sent and nothing is written: a fork, a session the server ended, or a copy being removed. */
    val stopped: Boolean get() = forked || endedByServer || removingForPolicy
    var nextFailure: ItemFailure? = null
    var rollbackNext = false
    var syncCount = 0
    private var serial = 1L
    private var rev = 1L

    fun freshId(): String = "00000000-0000-4000-8000-" + (++serial).toString().padStart(12, '0')

    companion object {
        const val BREACH_COUNT = 42L
    }

    override val halted: Boolean get() = stopped
    override val personalVaultId: String? get() = personal

    override suspend fun hydrate() {}

    override fun items(): List<VaultItem> = overlay().values.sortedBy { it.doc.name.lowercase() }

    override fun item(itemId: String): VaultItem? = overlay()[itemId]

    private fun overlay(): Map<String, VaultItem> {
        val byId = LinkedHashMap<String, VaultItem>()
        for ((id, item) in live) if (vaults.containsKey(item.vaultId)) byId[id] = item
        for (q in queue) {
            if (q.doc == null) byId.remove(q.itemId) else byId[q.itemId] = VaultItem(q.itemId, q.vaultId, byId[q.itemId]?.rev ?: 0, nowMs, q.doc)
        }
        return byId
    }

    override fun pendingSyncItemIds(): Set<String> = queue.mapTo(LinkedHashSet()) { it.itemId }

    /** The fake's queue is sent whole or not at all: the server never refuses a change of it for good. */
    override fun takeRefusedForGood(): Map<String, ItemFailure> = emptyMap()

    /** The fake keeps no files a server could remove: nothing is asked before its queue is sent. */
    override var beforeDrain: io.silencelen.andvari.core.client.items.BeforeDrain? = null

    /** How many times the vaults were read (the engine decrypts each name on every read). */
    var vaultReads = 0

    override fun vaults(): List<VaultView> = vaults.also { vaultReads++ }.map { (id, v) ->
        VaultView(id, if (v.personal) "personal" else "shared", v.name, v.role, v.standing, v.standing == VaultStanding.VERIFIED && v.role != VaultAccess.ROLE_READER && id !in closedMarks, closedMarks[id])
    }.sortedWith(compareBy({ it.type != "personal" }, { it.name.lowercase() }))

    override fun notices(): List<ItemNotice> = noticeList.toList()

    override fun dismissNotice(id: String) {
        noticeList.removeAll { it.id == id }
    }

    /** The scripted failure, once. */
    private fun scripted(): ItemFailure? = nextFailure.also { nextFailure = null }

    override suspend fun sync(): ItemResult<SyncReport> {
        if (stopped) return ItemResult.Failed(ItemFailure.Halted)
        scripted()?.let { return ItemResult.Failed(it) }
        if (offline) return ItemResult.Failed(ItemFailure.Unreachable(NoAnswerKind.TRANSPORT))
        syncCount++
        if (rollbackNext) {
            rollbackNext = false
            if (noticeList.none { it.kind == ItemNotice.ROLLBACK }) noticeList.add(ItemNotice(freshId(), "", "", ItemNotice.ROLLBACK))
            return ItemResult.Failed(ItemFailure.Rollback(unsolicitedFull = false))
        }
        drain()
        return ItemResult.Ok(SyncReport(rev, false, quotaUse))
    }

    /** Send what waits, as the engine does: what waits for a vault closed for writing stays queued until the mark goes. */
    private fun drain() {
        val held = queue.filter { it.vaultId in closedMarks }
        for (q in queue) if (q.vaultId !in closedMarks) apply(q)
        queue.clear()
        queue.addAll(held)
    }

    // ---- the account's own use and limits (spec 03 §14.4), as the engine counts them ----

    var quotaUse: io.silencelen.andvari.core.model.wire.QuotaUse? = null
    var lastSpaceAsked: io.silencelen.andvari.core.client.items.CopySize? = null
    var spaceChecks = 0
    private val codec = io.silencelen.andvari.core.client.items.ItemCodec(crypto)

    override fun quota(): io.silencelen.andvari.core.model.wire.QuotaUse? = quotaUse

    /** As [io.silencelen.andvari.core.client.items.ItemEngine.roomFor]: a sync, then the check on what it served. */
    override suspend fun roomFor(size: io.silencelen.andvari.core.client.items.CopySize): ItemResult<io.silencelen.andvari.core.client.items.QuotaRoom> {
        lastSpaceAsked = size
        spaceChecks++
        val s = sync()
        if (s is ItemResult.Failed && s.why !is ItemFailure.Denied) return s
        return ItemResult.Ok(io.silencelen.andvari.core.client.items.QuotaCheck.room(quotaUse, size))
    }

    override fun importSize(items: List<CsvImport.PlannedItem>): io.silencelen.andvari.core.client.items.CopySize =
        io.silencelen.andvari.core.client.items.CopySize(items.fold(0L) { sum, it -> sum + codec.sealedLength(it.doc) }, items.size.toLong())

    override fun copySize(docs: List<ItemDoc>, fileMaxBytes: Long, newVaultName: String?): io.silencelen.andvari.core.client.items.CopySize =
        io.silencelen.andvari.core.client.items.ItemEngine.sizeOf(codec, docs, fileMaxBytes, newVaultName)

    private fun apply(q: Queued) {
        val old = live[q.itemId]
        if (old != null) versions.getOrPut(q.itemId) { ArrayList() }.add(0, DecryptedItemVersion(old.rev, nowMs, old.doc))
        versions[q.itemId]?.let { while (it.size > 10) it.removeAt(it.size - 1) }
        if (q.doc == null) {
            live.remove(q.itemId)
            if (old != null) {
                deleted[q.itemId] = DeletedItemView(q.itemId, q.vaultId, nowMs, old.doc)
                for (a in old.doc.attachments) blobs.remove(a.id) // a deleted item's files go with it (spec 02 §7)
            }
        } else {
            live[q.itemId] = VaultItem(q.itemId, q.vaultId, ++rev, nowMs, q.doc)
        }
    }

    /** Whether the pretend server can be asked now: stopped, a scripted failure, or no answer. */
    private fun unreachable(): ItemFailure? = when {
        stopped -> ItemFailure.Halted
        else -> scripted() ?: if (offline) ItemFailure.Unreachable(NoAnswerKind.TRANSPORT) else null
    }

    override suspend fun uploadEncryptedAttachment(attachmentId: String, itemId: String, vaultId: String, sealed: ByteArray): ItemResult<Unit> {
        unreachable()?.let { return ItemResult.Failed(it) }
        refusal(vaultId)?.let { return ItemResult.Failed(ItemFailure.NotAllowed(it)) }
        blobs[attachmentId] = vaultId to sealed.copyOf()
        return ItemResult.Ok(Unit)
    }

    override suspend fun downloadAttachment(ref: AttachmentRef): ItemResult<ByteArray> {
        unreachable()?.let { return ItemResult.Failed(it) }
        // As the engine: a file key that is not one is damaged content, refused before anything is decrypted.
        val fileKey = ItemCodec.fileKeyOf(ref) ?: return ItemResult.Failed(ItemFailure.Corrupt("content"))
        val body = blobs[ref.id]?.second ?: return ItemResult.Failed(ItemFailure.Refused("not_found", 404)).also { fileKey.fill(0) }
        return try {
            ItemResult.Ok(Attachments.decrypt(crypto, fileKey, body.copyOfRange(0, Attachments.HEADER_BYTES), body.copyOfRange(Attachments.HEADER_BYTES, body.size)))
        } catch (e: KeysGoneException) {
            throw e
        } catch (e: Exception) {
            ItemResult.Failed(ItemFailure.Corrupt("content"))
        } finally {
            fileKey.fill(0)
        }
    }

    override suspend fun itemVersions(itemId: String, vaultId: String): ItemResult<List<DecryptedItemVersion>> {
        unreachable()?.let { return ItemResult.Failed(it) }
        return ItemResult.Ok(versions[itemId].orEmpty().toList())
    }

    override fun versionDocForRestore(itemId: String, version: ItemDoc): ItemDoc {
        val liveIds = item(itemId)?.doc?.attachments?.mapTo(HashSet()) { it.id } ?: return version
        return version.copy(attachments = version.attachments.filter { it.id in liveIds })
    }

    /** The pretend server answers a restore and a delete for good as done and stores nothing. */
    var trashActionsStoreNothing = false

    /** Trash rows the device never held and has not read yet: the trash lists them with no document until a restore reads one. */
    val notReadYet = HashSet<String>()

    /** How many trash rows' documents were read one by one (the engine's call per row it never held). */
    var trashDocReads = 0

    override suspend fun deletedItems(): ItemResult<List<DeletedItemView>> {
        unreachable()?.let { return ItemResult.Failed(it) }
        return ItemResult.Ok(deleted.values.map { if (it.itemId in notReadYet) it.copy(doc = null, notRead = true) else it })
    }

    override suspend fun deletedItemDoc(row: DeletedItemView): ItemResult<ItemDoc?> {
        unreachable()?.let { return ItemResult.Failed(it) }
        trashDocReads++
        notReadYet.remove(row.itemId)
        return ItemResult.Ok(deleted[row.itemId]?.doc)
    }

    /** The pretend server's `GET /vaults/deleted`, as the engine would answer it. */
    val deletedVaultList = ArrayList<io.silencelen.andvari.core.client.items.DeletedVault>()

    override suspend fun deletedVaults(): ItemResult<List<io.silencelen.andvari.core.client.items.DeletedVault>> {
        unreachable()?.let { return ItemResult.Failed(it) }
        return ItemResult.Ok(deletedVaultList.sortedByDescending { it.deletedAt })
    }

    override suspend fun restoreDeleted(itemId: String, vaultId: String, doc: ItemDoc): ItemResult<Unit> {
        unreachable()?.let { return ItemResult.Failed(it) }
        refusal(vaultId)?.let { return ItemResult.Failed(ItemFailure.NotAllowed(it)) }
        if (itemId !in deleted) return ItemResult.Failed(ItemFailure.Refused("not_found", 404))
        if (trashActionsStoreNothing) return ItemResult.Ok(Unit)
        deleted.remove(itemId)
        notReadYet.remove(itemId)
        live[itemId] = VaultItem(itemId, vaultId, ++rev, nowMs, doc.copy(attachments = emptyList()))
        return ItemResult.Ok(Unit)
    }

    override fun planMove(itemId: String, targetVaultId: String, deleteSource: Boolean): ItemResult<MovePlan> {
        val src = live[itemId] ?: return ItemResult.Failed(ItemFailure.NotAllowed(ItemRefusal.ITEM_GONE))
        return ItemResult.Ok(planFor(src, targetVaultId, deleteSource))
    }

    private fun planFor(src: VaultItem, targetVaultId: String, deleteSource: Boolean) = MovePlan(
        freshId(), src.itemId, src.vaultId, src.rev, targetVaultId, freshId(), deleteSource,
        src.doc.attachments.map { MovedAttachment(it.id, freshId(), Bytes.toB64(crypto.randomBytes(32)), it.name, it.size) },
    )

    /** The copy leg: the item and its files under the plan's ids and keys; idempotent per plan. Answers files left out. */
    private fun copyLeg(src: VaultItem, plan: MovePlan): Int {
        var leftOut = 0
        if (live[plan.targetItemId] == null) {
            val refs = plan.attachments.mapNotNull { a ->
                val old = src.doc.attachments.first { it.id == a.oldId }
                val body = blobs[a.oldId]?.second ?: run {
                    leftOut++
                    return@mapNotNull null
                }
                val plain = Attachments.decrypt(crypto, Bytes.fromB64(old.fileKey), body.copyOfRange(0, Attachments.HEADER_BYTES), body.copyOfRange(Attachments.HEADER_BYTES, body.size))
                val enc = Attachments.encrypt(crypto, Bytes.fromB64(a.newFileKey), plain)
                blobs[a.newId] = plan.targetVaultId to (enc.header + enc.ciphertext)
                AttachmentRef(a.newId, a.name, a.size, a.newFileKey)
            }
            live[plan.targetItemId] = VaultItem(plan.targetItemId, plan.targetVaultId, ++rev, nowMs, src.doc.copy(attachments = refs))
        }
        return leftOut
    }

    override suspend fun runMove(plan: MovePlan, onProgress: ((done: Int, total: Int) -> Unit)?, finalSync: Boolean): ItemResult<Unit> {
        unreachable()?.let { return ItemResult.Failed(it) }
        val src = live[plan.sourceItemId] ?: return ItemResult.Failed(ItemFailure.NotAllowed(ItemRefusal.ITEM_GONE))
        if (src.vaultId != plan.sourceVaultId) return ItemResult.Failed(ItemFailure.NotAllowed(ItemRefusal.ITEM_CHANGED_VAULTS))
        refusal(plan.targetVaultId)?.let { return ItemResult.Failed(ItemFailure.NotAllowed(it)) }
        if (plan.deleteSource) refusal(plan.sourceVaultId)?.let { return ItemResult.Failed(ItemFailure.NotAllowed(it)) }
        copyLeg(src, plan)
        if (plan.deleteSource) {
            if (src.rev != plan.sourceRev) return ItemResult.Failed(ItemFailure.NotAllowed(ItemRefusal.ITEM_CHANGED))
            apply(Queued(src.itemId, src.vaultId, null))
        }
        return ItemResult.Ok(Unit)
    }

    override suspend fun rescueToPersonal(vaultId: String, onProgress: ((done: Int, total: Int) -> Unit)?): ItemResult<Int> {
        val home = personal ?: return ItemResult.Failed(ItemFailure.NotAllowed(ItemRefusal.NO_PERSONAL_VAULT))
        val sources = live.values.filter { it.vaultId == vaultId }
        var copied = 0
        for (src in sources) {
            val plan = bulkPlans.getOrPut("$vaultId|${src.itemId}|$home") { planFor(src, home, false) }
            val r = runMove(plan, null, false)
            if (r is ItemResult.Failed) return r
            onProgress?.invoke(++copied, sources.size)
        }
        return ItemResult.Ok(copied)
    }

    override suspend fun rescueHeldToPersonal(vaultId: String, onProgress: ((done: Int, total: Int) -> Unit)?): ItemResult<HeldRescue> {
        unreachable()?.let { return ItemResult.Failed(it) }
        val home = personal ?: return ItemResult.Failed(ItemFailure.NotAllowed(ItemRefusal.NO_PERSONAL_VAULT))
        val h = held[vaultId]?.takeIf { it.readable } ?: return ItemResult.Failed(ItemFailure.NotAllowed(ItemRefusal.VAULT_NOT_OPEN))
        var copied = 0
        var leftOut = 0
        for (src in h.items) {
            val plan = bulkPlans.getOrPut("held|$vaultId|${src.itemId}|$home") { planFor(src, home, false) }
            leftOut += copyLeg(src, plan)
            onProgress?.invoke(++copied, h.items.size)
        }
        return ItemResult.Ok(HeldRescue(copied, leftOut))
    }

    /** As the engine: the held copy while it can be read, else the rows of a vault still open. Null: none to read. */
    private fun heldSources(fromVaultId: String): Map<String, VaultItem>? {
        val h = held[fromVaultId]
        if (h != null && !h.readable) return null
        val out = (h?.items ?: live.values.filter { it.vaultId == fromVaultId }).associateByTo(LinkedHashMap()) { it.itemId }
        // As the engine: a change still waiting (a vault closed for writing holds it back, or it was parked with the held
        // copy when the vault left) is what is copied.
        for (q in waitingRows(fromVaultId)) if (q.doc != null) {
            val prior = out[q.itemId]
            out[q.itemId] = VaultItem(q.itemId, fromVaultId, prior?.rev ?: 0, prior?.updatedAt ?: 0, q.doc)
        }
        return out
    }

    /** The changes of [vaultId] that wait, in order: parked with its held copy, or queued while it is open. */
    private fun waitingRows(vaultId: String): List<Queued> = held[vaultId]?.parked ?: queue.filter { it.vaultId == vaultId }

    /** As the engine ([io.silencelen.andvari.core.client.items.ItemEngine.waitingChanges]). */
    fun waitingChanges(vaultId: String): Set<String> = waitingRows(vaultId).mapTo(LinkedHashSet()) { it.itemId }

    /**
     * As the engine ([io.silencelen.andvari.core.client.items.ItemEngine.waitingDeletions]): the items of [fromVaultId]
     * whose last waiting change is their deletion, queued while it is open or parked with its held copy. This pretend
     * server has no other writer, so every such deletion is on the revision this device holds.
     */
    private fun waitingDeleted(fromVaultId: String): Set<String> {
        val h = held[fromVaultId]
        val last = LinkedHashMap<String, Queued>()
        for (q in waitingRows(fromVaultId)) last[q.itemId] = q
        val there: (String) -> Boolean = if (h != null) { id -> h.items.any { it.itemId == id } } else { id -> live[id]?.vaultId == fromVaultId }
        return last.values.filter { it.doc == null && there(it.itemId) }.mapTo(LinkedHashSet()) { it.itemId }
    }

    /** As the engine: the copy's id derived from the held item, its rev and a change waiting, so a second run finds it. */
    private fun heldCopyId(fromVaultId: String, src: VaultItem, targetVaultId: String): String {
        val waiting = waitingRows(fromVaultId).lastOrNull { it.itemId == src.itemId && it.doc != null }?.let { "|w" + it.doc.hashCode() } ?: ""
        return Bytes.uuidV4FromBytes(crypto.sha256("held-copy|$fromVaultId|${src.itemId}|${src.rev}|$targetVaultId$waiting".encodeToByteArray()))
    }

    override fun heldDocsToBring(fromVaultId: String, targetVaultId: String, picks: List<io.silencelen.andvari.core.client.items.HeldPick>): List<ItemDoc> {
        val sources = heldSources(fromVaultId) ?: return emptyList()
        val deleted = waitingDeleted(fromVaultId)
        return picks.distinctBy { it.itemId }.filter { it.itemId !in deleted }.mapNotNull { p ->
            sources[p.itemId]?.takeIf { live[heldCopyId(fromVaultId, it, targetVaultId)]?.vaultId != targetVaultId }?.doc
        }
    }

    override suspend fun bringHeldInto(
        fromVaultId: String,
        targetVaultId: String,
        picks: List<io.silencelen.andvari.core.client.items.HeldPick>,
        onMade: (io.silencelen.andvari.core.client.items.HeldCopied) -> Unit,
        onProgress: ((done: Int, total: Int) -> Unit)?,
        onDeleted: (io.silencelen.andvari.core.client.items.HeldDeleted) -> Unit,
    ): ItemResult<List<io.silencelen.andvari.core.client.items.HeldCopied>> {
        unreachable()?.let { return ItemResult.Failed(it) }
        if (fromVaultId == targetVaultId) return ItemResult.Failed(ItemFailure.NotAllowed(ItemRefusal.VAULT_READ_ONLY))
        refusal(targetVaultId)?.let { return ItemResult.Failed(ItemFailure.NotAllowed(it)) }
        val sources = heldSources(fromVaultId) ?: return ItemResult.Failed(ItemFailure.NotAllowed(ItemRefusal.VAULT_NOT_OPEN))
        val chosen = picks.distinctBy { it.itemId }.map { p ->
            val src = sources[p.itemId] ?: return ItemResult.Failed(ItemFailure.NotAllowed(ItemRefusal.ITEM_GONE))
            val earlier = p.replaces?.let { live[it] }
            if (earlier != null && earlier.vaultId != targetVaultId) return ItemResult.Failed(ItemFailure.NotAllowed(ItemRefusal.ITEM_CHANGED_VAULTS))
            p to src
        }
        val made = ArrayList<io.silencelen.andvari.core.client.items.HeldCopied>()
        val deleted = waitingDeleted(fromVaultId)
        // As the engine: an earlier copy goes only at the revision the pick names, with no change of its own waiting, and
        // is kept (said why) otherwise; null when it went or is gone.
        fun dropEarlier(p: io.silencelen.andvari.core.client.items.HeldPick, earlierId: String): String? {
            val earlier = live[earlierId] ?: return null
            if (earlier.vaultId != targetVaultId) return io.silencelen.andvari.core.client.items.HeldDeleted.KEPT_CHANGED
            val atRev = p.replacesAtRev ?: return io.silencelen.andvari.core.client.items.HeldDeleted.KEPT_NO_REVISION
            if (earlier.rev != atRev || queue.any { it.itemId == earlierId }) return io.silencelen.andvari.core.client.items.HeldDeleted.KEPT_CHANGED
            apply(Queued(earlierId, targetVaultId, null))
            return null
        }
        var done = 0
        for ((p, src) in chosen) {
            if (src.itemId in deleted) {
                // As the engine: the person's deletion is carried, never the item; the earlier copy goes as a replaced one.
                val keptBecause = p.replaces?.let { dropEarlier(p, it) }
                onDeleted(io.silencelen.andvari.core.client.items.HeldDeleted(src.itemId, src.rev, p.replaces, keptBecause != null, keptBecause))
                onProgress?.invoke(++done, chosen.size)
                continue
            }
            val madeId = heldCopyId(fromVaultId, src, targetVaultId)
            val plan = bulkPlans.getOrPut("held-copy|$madeId") { planFor(src, targetVaultId, false).copy(targetItemId = madeId) }
            val found = live[madeId]
            val leftOut = if (found != null) (src.doc.attachments.size - found.doc.attachments.size).coerceAtLeast(0) else copyLeg(src, plan)
            val keptBecause = p.replaces?.takeIf { it != madeId }?.let { dropEarlier(p, it) }
            val one = io.silencelen.andvari.core.client.items.HeldCopied(src.itemId, src.rev, madeId, leftOut, keptBecause != null, keptBecause, live[madeId]?.rev)
            made += one
            onMade(one)
            onProgress?.invoke(++done, chosen.size)
        }
        return ItemResult.Ok(made)
    }

    override fun heldVaults(): List<HeldVaultView> = held.map { (id, h) ->
        HeldVaultView(id, h.name.takeIf { h.readable }, h.reason, h.items.size, h.parked.size, h.expungeAt, h.readable, ownedHere = h.owned)
    }

    override fun heldItems(vaultId: String): List<VaultItem> = held[vaultId]?.takeIf { it.readable }?.items.orEmpty()

    override fun removeFromDevice(vaultId: String): ItemResult<Unit> {
        if (stopped) return ItemResult.Failed(ItemFailure.Halted)
        if (held.remove(vaultId) != null) return ItemResult.Ok(Unit)
        val v = vaults[vaultId]
        if (v == null || v.personal || v.standing == VaultStanding.VERIFIED) return ItemResult.Failed(ItemFailure.NotAllowed(ItemRefusal.VAULT_READ_ONLY))
        vaults.remove(vaultId)
        live.values.filter { it.vaultId == vaultId }.forEach { live.remove(it.itemId) }
        queue.removeAll { it.vaultId == vaultId }
        return ItemResult.Ok(Unit)
    }

    override suspend fun renameVault(vaultId: String, newName: String): ItemResult<Unit> {
        unreachable()?.let { return ItemResult.Failed(it) }
        refusal(vaultId)?.let { return ItemResult.Failed(ItemFailure.NotAllowed(it)) }
        vaults.getValue(vaultId).name = newName
        return ItemResult.Ok(Unit)
    }

    override fun envelopes(): List<SyncItem> = emptyList()

    /** Passwords the pretend breach corpus holds, each seen [BREACH_COUNT] times. */
    val breached = HashSet<String>()

    override suspend fun breachRange(prefix: String): ItemResult<String> {
        unreachable()?.let { return ItemResult.Failed(it) }
        val lines = breached.map { Hibp.sha1UpperHex(crypto, it) }.filter { Hibp.prefix(it) == prefix.uppercase() }.map { it.drop(5) + ":" + BREACH_COUNT }
        return ItemResult.Ok(lines.joinToString("\r\n"))
    }

    override fun importProjections(vaultId: String?): ItemResult<CsvImport.ImportProjections> {
        val target = vaultId ?: personal ?: return ItemResult.Failed(ItemFailure.NotAllowed(ItemRefusal.NO_PERSONAL_VAULT))
        return ItemResult.Ok(CsvImport.projections(items().filter { it.vaultId == target }.map { it.doc }))
    }

    override suspend fun importAll(
        items: List<CsvImport.PlannedItem>,
        onProgress: ((done: Int, total: Int) -> Unit)?,
        vaultId: String?,
        onStopped: (io.silencelen.andvari.core.client.items.ImportStopped) -> Unit,
    ): ItemResult<Unit> {
        // Nothing is sent at all with no answer, so nothing is kept or half done: the plain failure is the whole story.
        unreachable()?.let { return ItemResult.Failed(it) }
        val target = vaultId ?: personal ?: return ItemResult.Failed(ItemFailure.NotAllowed(ItemRefusal.NO_PERSONAL_VAULT))
        refusal(target)?.let { return ItemResult.Failed(ItemFailure.NotAllowed(it)) }
        var done = 0
        for (p in items) {
            // The planned id doubles as the mutation id: a replay of the same plan lands each item once.
            if (live[p.itemId] == null) apply(Queued(p.itemId, target, p.doc))
            onProgress?.invoke(++done, items.size)
        }
        return ItemResult.Ok(Unit)
    }

    override suspend fun purgeDeleted(itemId: String, vaultId: String): ItemResult<Unit> {
        unreachable()?.let { return ItemResult.Failed(it) }
        refusal(vaultId)?.let { return ItemResult.Failed(ItemFailure.NotAllowed(it)) }
        if (trashActionsStoreNothing) return ItemResult.Ok(Unit)
        deleted.remove(itemId)
        versions.remove(itemId)
        return ItemResult.Ok(Unit)
    }

    /** The trash actions answered as done, as the engine keeps them in the account's cache (they outlive a lock). */
    private val trashDone = ArrayList<io.silencelen.andvari.core.client.items.TrashActionDone>()

    override fun recordTrashAction(done: io.silencelen.andvari.core.client.items.TrashActionDone) {
        trashDone.removeAll { it.itemId == done.itemId }
        trashDone += done
    }

    override fun trashActionsDone(): List<io.silencelen.andvari.core.client.items.TrashActionDone> = trashDone.toList()

    override fun clearTrashActionsDone() = trashDone.clear()

    /** The vaults closed for writing, as the engine keeps them (they outlive a lock). */
    private val closedMarks = HashMap<String, io.silencelen.andvari.core.client.items.VaultClosedReason>()

    override fun markClosedForWriting(vaultId: String, reason: io.silencelen.andvari.core.client.items.VaultClosedReason?) {
        if (reason == null) closedMarks.remove(vaultId) else closedMarks[vaultId] = reason
    }

    override fun closedForWriting(vaultId: String): io.silencelen.andvari.core.client.items.VaultClosedReason? = closedMarks[vaultId]

    private fun refusal(vaultId: String): ItemRefusal? {
        val v = vaults[vaultId] ?: return ItemRefusal.VAULT_NOT_OPEN
        if (v.standing != VaultStanding.VERIFIED || v.role == VaultAccess.ROLE_READER) return ItemRefusal.VAULT_READ_ONLY
        return if (vaultId in closedMarks) ItemRefusal.VAULT_CLOSED_FOR_WRITING else null
    }

    /**
     * Send [q], or queue it with no answer: the engine's verdicts on a durable cache. As the engine does, a write that
     * gets through sends what waited before it too, so nothing is left waiting behind it.
     */
    private fun sendOrQueue(q: Queued): ItemResult<Written> {
        scripted()?.let { return ItemResult.Failed(it) }
        if (offline) {
            queue.add(q)
            return ItemResult.Ok(Written.QUEUED)
        }
        drain()
        apply(q)
        return ItemResult.Ok(Written.APPLIED)
    }

    override suspend fun save(
        itemId: String?,
        doc: ItemDoc,
        vaultId: String?,
        uploads: List<NewAttachment>,
        onProgress: ((done: Int, total: Int) -> Unit)?,
        draftItemId: String?,
        baseItemRev: Long?,
        onQueued: (() -> Unit)?,
    ): ItemResult<SavedItem> {
        if (stopped) return ItemResult.Failed(ItemFailure.Halted)
        val existing = itemId?.let { item(it) ?: return ItemResult.Failed(ItemFailure.NotAllowed(ItemRefusal.ITEM_GONE)) }
        val target = if (existing != null) {
            if (vaultId == null) return ItemResult.Failed(ItemFailure.NotAllowed(ItemRefusal.EDIT_UNBOUND))
            if (vaultId != existing.vaultId) return ItemResult.Failed(ItemFailure.NotAllowed(ItemRefusal.ITEM_CHANGED_VAULTS))
            vaultId
        } else {
            vaultId ?: personal ?: return ItemResult.Failed(ItemFailure.NotAllowed(ItemRefusal.NO_PERSONAL_VAULT))
        }
        refusal(target)?.let { return ItemResult.Failed(ItemFailure.NotAllowed(it)) }
        // The server's per-row verdict for a file it does not hold (spec 03 §5 `rejected`).
        if (!offline && doc.attachments.any { it.id !in blobs }) return ItemResult.Failed(ItemFailure.Refused("unknown_attachment", 400))
        val id = itemId ?: draftItemId ?: freshId()
        onQueued?.invoke()
        return when (val r = sendOrQueue(Queued(id, target, doc))) {
            is ItemResult.Ok -> ItemResult.Ok(SavedItem(id, r.value))
            is ItemResult.Failed -> r
        }
    }

    override suspend fun remove(itemId: String): ItemResult<Written> {
        if (stopped) return ItemResult.Failed(ItemFailure.Halted)
        val existing = item(itemId) ?: return ItemResult.Ok(Written.APPLIED)
        refusal(existing.vaultId)?.let { return ItemResult.Failed(ItemFailure.NotAllowed(it)) }
        // As the engine does: the item's unsent edits fold into the delete, and an item never sent is only dropped.
        queue.removeAll { it.itemId == itemId && it.doc != null }
        if (live[itemId] == null) return ItemResult.Ok(Written.APPLIED)
        return sendOrQueue(Queued(itemId, existing.vaultId, null))
    }
}
