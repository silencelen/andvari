package io.silencelen.andvari.core.app.content

import io.silencelen.andvari.core.app.ActionResult
import io.silencelen.andvari.core.app.AttachmentContent
import io.silencelen.andvari.core.app.AttachmentDraftView
import io.silencelen.andvari.core.app.AttachmentLimitsView
import io.silencelen.andvari.core.app.AttachmentRules
import io.silencelen.andvari.core.app.AttachmentView
import io.silencelen.andvari.core.app.CardDetail
import io.silencelen.andvari.core.app.CardInput
import io.silencelen.andvari.core.app.CopyProgressView
import io.silencelen.andvari.core.app.ExportFile
import io.silencelen.andvari.core.app.ExportKind
import io.silencelen.andvari.core.app.GeneratorSettings
import io.silencelen.andvari.core.app.ItemDetail
import io.silencelen.andvari.core.app.ItemHistoryView
import io.silencelen.andvari.core.app.ItemSummary
import io.silencelen.andvari.core.app.ItemVersionView
import io.silencelen.andvari.core.app.TrashItemView
import io.silencelen.andvari.core.app.UploadView
import io.silencelen.andvari.core.client.AttachmentRef
import io.silencelen.andvari.core.client.DecryptedItemVersion
import io.silencelen.andvari.core.client.DeletedItemView
import io.silencelen.andvari.core.crypto.Attachments
import io.silencelen.andvari.core.crypto.Bytes
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.withContext
import kotlinx.datetime.toLocalDateTime
import io.silencelen.andvari.core.app.LoginInput
import io.silencelen.andvari.core.app.NoteInput
import io.silencelen.andvari.core.app.OneTimeCode
import io.silencelen.andvari.core.app.SecretField
import io.silencelen.andvari.core.app.Subscription
import io.silencelen.andvari.core.app.VaultChoiceView
import io.silencelen.andvari.core.app.VaultNoticeView
import io.silencelen.andvari.core.client.CardData
import io.silencelen.andvari.core.client.CardDisplay
import io.silencelen.andvari.core.client.ItemDoc
import io.silencelen.andvari.core.client.LoginData
import io.silencelen.andvari.core.client.VaultItem
import io.silencelen.andvari.core.client.autofill.CardNormalize
import io.silencelen.andvari.core.client.net.NoAnswerKind
import io.silencelen.andvari.core.client.autofill.SavedUri
import io.silencelen.andvari.core.client.autofill.UriMatch
import io.silencelen.andvari.core.app.CredentialIdentity
import io.silencelen.andvari.core.app.FillCard
import io.silencelen.andvari.core.app.FillCredential
import io.silencelen.andvari.core.app.FillLogin
import io.silencelen.andvari.core.client.items.CopySize
import io.silencelen.andvari.core.client.items.HeldCopied
import io.silencelen.andvari.core.client.items.HeldPick
import io.silencelen.andvari.core.client.items.ItemFailure
import io.silencelen.andvari.core.client.items.QuotaCheck
import io.silencelen.andvari.core.client.items.TrashActionDone
import io.silencelen.andvari.core.client.items.VaultClosedReason
import io.silencelen.andvari.core.trust.TrustGrammar
import io.silencelen.andvari.core.client.items.ItemRefusal
import io.silencelen.andvari.core.client.items.ItemResult
import io.silencelen.andvari.core.client.items.LockedBeforeKept
import io.silencelen.andvari.core.client.items.MovePlan
import io.silencelen.andvari.core.client.items.VaultAccess
import io.silencelen.andvari.core.client.items.VaultStanding
import io.silencelen.andvari.core.client.items.VaultView
import io.silencelen.andvari.core.client.items.Written
import io.silencelen.andvari.core.model.wire.SyncItem
import io.silencelen.andvari.core.crypto.CryptoProvider
import io.silencelen.andvari.core.crypto.GeneratorOptions
import io.silencelen.andvari.core.crypto.KeysGoneException
import io.silencelen.andvari.core.crypto.PasswordGenerator
import io.silencelen.andvari.core.crypto.Totp
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Job
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow

/**
 * The one implementation of [VaultContent]'s rules, over a [ContentSource]: [EngineVaultContent] gives it the item
 * engine, [FakeVaultContent] an in-memory source. Everything a screen can tell apart (validation, sentences, what is
 * writable, what the list shows) is decided here, once, so the fake behaves as the real thing does.
 *
 * [host] is the session's: the clock, the policy's limits, and what a backup records of the account.
 */
internal class ContentController(
    private val source: ContentSource,
    private val crypto: CryptoProvider,
    private val host: ContentHost,
    /** Where moves, saves with files and the save queue are kept across a lock; null keeps them for this instance only. */
    keeping: ContentKeeping?,
    /** Where a host without [keeping] holds what a lock cut short across its unlocks (the fake's); null: this instance only. */
    unsavedHolder: UnsavedAtLock? = null,
) : VaultContent {
    /** The account's seals for what is kept on this device; null with no host storage. */
    private val records: LocalRecords? = keeping?.let { LocalRecords(it.account, crypto) }

    /**
     * Changes a lock overtook before they were kept: this instance notes them as its intents end after the lock, and the
     * next unlock's instance (the same holder, from the process's [ContentStores]) says them as its [ContentState.notice].
     */
    private val unsaved: UnsavedAtLock = keeping?.unsaved ?: unsavedHolder ?: UnsavedAtLock()

    /** Moves and copies that did not finish, by item, target and kind: Try again replays the same ids. */
    private val moves = ContentMoves(
        if (keeping != null && records != null) ContentMoves.SealedStore(keeping.moves, records) { droppedEarlier(it) } else ContentMoves.MemoryStore(),
    )

    /** Saves with new files, kept until they are done. */
    private val kept: ContentKeptSaves =
        if (keeping != null && records != null) ContentKeptSaves(keeping.keptSaves, keeping.files, records) { droppedEarlier(it) } else ContentKeptSaves.inMemory()

    /** The iPhone's AutoFill snapshot, sealed under the account's vault key; null on a host with no extension that reads one. */
    private val fillWriter: FillSnapshotWriter? =
        keeping?.takeIf { it.fill !== io.silencelen.andvari.core.app.FillSnapshotStore.None }?.let { FillSnapshotWriter(it.fill, it.account, crypto) }

    /** Records an earlier version kept that this one could not carry over, removed: said once, counted. */
    private var droppedEarlierCount = 0

    private fun droppedEarlier(count: Int) {
        if (count <= 0) return
        droppedEarlierCount += count
        say(ContentCopy.earlierRecords(droppedEarlierCount), ContentNoticeKind.RECORDS)
    }

    /** The kept saves were looked at after this unlock's first sync. */
    private var keptResumed = false

    /** When this unlock last put each kept file on the server (wall clock): a drain soon after sends none again. */
    private val keptFileSentAt = HashMap<String, Long>()

    /** Asked before every drain of the queue: the files of a kept save whose change waits there go up again first. */
    private val drainHook: io.silencelen.andvari.core.client.items.BeforeDrain = { puts -> filesBeforeDrain(puts) }

    init {
        source.beforeDrain = drainHook
    }

    /** The extensions' save queue and the list of automatic saves; null on a host that gave no storage. */
    private val saves: ContentSaves? = if (keeping != null && records != null) {
        ContentSaves(
            keeping.queue, keeping.applied, records, source, crypto, { host.wallMs() },
            write = { itemId, doc, vaultId, newItemId -> queueWrite(itemId, doc, vaultId, newItemId) },
            remove = { itemId -> if (source.halted) ItemResult.Failed(ItemFailure.Halted) else source.remove(itemId) },
            personalWritable = { source.personalVaultId?.let { writable(it) } == true },
            vaultName = { vaultName(it) },
            alive = { !closed },
            dropped = { droppedEarlier(it) },
        )
    } else {
        null
    }

    /** The write path of a save from the queue: the editors' rules (a stopped server writes nothing), the engine's save. */
    private suspend fun queueWrite(itemId: String?, doc: ItemDoc, vaultId: String, newItemId: String?): ItemResult<io.silencelen.andvari.core.client.items.SavedItem> {
        if (source.halted) return ItemResult.Failed(ItemFailure.Halted)
        if (!writable(vaultId)) return ItemResult.Failed(ItemFailure.NotAllowed(if (source.closedForWriting(vaultId) != null) ItemRefusal.VAULT_CLOSED_FOR_WRITING else ItemRefusal.VAULT_READ_ONLY))
        return source.save(itemId, doc, vaultId, emptyList(), null, newItemId, null)
    }

    private fun wallMs(): Long = host.wallMs()
    private fun limits(): AttachmentLimitsView = host.attachmentLimits()

    private var closed = false
    private var opened = false
    private var revision = 0L
    private var query = ""
    private var sync = VaultSyncState.NOT_YET
    private var syncs = 0
    private var busyCount = 0

    /** The person's writes and the quiet syncs running now ([settled]). */
    private val writing = kotlinx.coroutines.flow.MutableStateFlow(0)

    /**
     * Returns once no write of the person's and no quiet sync is running in this content. A policy's one attempt that
     * counted a request one of them had out waits here before it removes the copy, so that write answers what became of
     * it (made, or not) instead of finding the content gone.
     */
    internal suspend fun settled() {
        writing.first { it == 0 }
    }

    private var error: String? = null
    private var notice: String? = null
    private var noticeKind: ContentNoticeKind? = null
    private var lockCut: List<LockCut> = emptyList()

    /** [text] becomes the notice, of [kind] ([ContentState.noticeKind]); [cuts] only with [ContentNoticeKind.LOCK]. */
    private fun say(text: String, kind: ContentNoticeKind, cuts: List<LockCut> = emptyList()) {
        notice = text
        noticeKind = kind
        lockCut = cuts
    }

    /** The editors whose save runs now, by item id ([NEW_ITEM] for a new one): a second tap is not a second save. */
    private val saving = HashSet<String>()

    /** The trash as last read, by item, while it is open. */
    private var trashRead: Map<String, DeletedItemView>? = null

    /** The open history: whose, and its versions decrypted. */
    private var historyRead: Pair<String, List<DecryptedItemVersion>>? = null

    /** Moved on by every open and close of a screen that reads as it opens: a read that finishes late assigns nothing. */
    private var trashToken = 0L
    private var historyToken = 0L
    private var deletedVaultsToken = 0L

    /** The owner's "Recently deleted" list as last read, while it is open. */
    private var deletedVaultsRead: List<io.silencelen.andvari.core.app.DeletedVaultView>? = null

    /** The open editor's files. */
    private var draft: Draft? = null
    private var upload: UploadView? = null

    /** A copy of a vault's items into the personal vault, while it runs: one at a time. */
    private var copying: CopyProgressView? = null

    /** The last check before a large copy that has something to say ([ContentState.space]). */
    private var space: SpaceCheck? = null

    /** Import and export, with their screens' sessions. */
    private val ports = ContentPorts(
        source, crypto, host, { vaultsForNewItems() }, { vaultName(it) }, { kept, lost -> unsaved.import(kept, lost) },
        owned = { ownedHere(it) }, checked = { said(it) },
    )

    /** Vault health, its screen and the session's breach verdicts. */
    private val healthPart = ContentHealth(source, crypto, host, { roleForWrite(it) }, { id, doc -> healthSave(id, doc) }, { id -> healthRemove(id) })

    private val flow = MutableStateFlow(build())
    private val listeners = LinkedHashMap<Int, (ContentState) -> Unit>()
    private var nextListener = 0

    override val state: ContentState get() = flow.value
    override val states: StateFlow<ContentState> get() = flow

    override fun observe(listener: (ContentState) -> Unit): Subscription {
        val key = nextListener++
        listeners[key] = listener
        listener(flow.value)
        return object : Subscription {
            override fun close() {
                listeners.remove(key)
            }
        }
    }

    override fun close() {
        closed = true
        listeners.clear()
        draft?.wipe()
        draft = null
        trashRead = null
        historyRead = null
        deletedVaultsRead = null
        usedAt.clear()
        // A lock is not a cancel: kept moves and kept saves stay in the host's storage for the next unlock.
        moves.forget()
        if (source.beforeDrain === drainHook) source.beforeDrain = null
        keptFileSentAt.clear()
        ports.close()
        healthPart.close()
    }

    // ---- state ----

    private fun build(): ContentState {
        if (!closed) unsaved.taken()?.let { say(it.text, ContentNoticeKind.LOCK, it.cuts) }
        // Halted for the policy's wipe is not a stopped server: the writes stay offered and each says why it is refused.
        val removing = source.halted && host.removingForPolicy()
        val stopped = source.halted && !removing
        val pending = source.pendingSyncItemIds()
        val q = query.trim().lowercase()
        // The vaults are read once for the whole list (the engine decrypts each name on every read): a row looks its
        // vault up in this map, so a list of thousands costs no more reads than a list of one.
        val held = source.vaults()
        val byVault = held.associateBy { it.vaultId }
        return ContentState(
            revision = ++revision,
            items = source.items().filter { matches(it, q) }.map { summaryOf(it, it.itemId in pending, byVault[it.vaultId], stopped) },
            query = query,
            vaults = held.map { contentVault(it, stopped) },
            vaultNotices = source.notices().map { n -> ContentCopy.notice(n).let { (text, warning) -> VaultNoticeView(n.id, text, warning) } },
            sync = if (stopped) VaultSyncState.STOPPED else sync,
            queued = pending.size,
            serverStopped = stopped,
            syncing = syncs > 0,
            busy = busyCount > 0,
            error = error,
            notice = notice,
            noticeKind = if (notice == null) null else noticeKind,
            lockCut = if (notice == null) emptyList() else lockCut,
            trash = trashRead?.let(::trashViews),
            history = historyRead?.let { (id, versions) -> historyView(id, versions) },
            attachmentDraft = draft?.let(::draftView),
            upload = upload,
            held = source.heldVaults().map { h ->
                // A copy closed because its person was added again cannot read its own name: the open invitation's is used.
                // Either name passes the server or a co-member: shown as one safe line, in the entry and in its line alike.
                val name = ItemText.label((if (h.addedAgain) host.openInvitationName(h.vaultId) else null) ?: h.name.orEmpty())
                HeldVaultRow(h.vaultId, name, ContentCopy.heldLine(h.reason, h.expungeAt, h.ownedHere, h.addedAgain, name, host.timeZone()), h.itemCount, h.readable, h.expungeAt)
            },
            copying = copying,
            csvImport = ports.importView(),
            exporting = ports.exportView(),
            health = healthPart.view(),
            pendingSaves = saves?.pendingViews().orEmpty(),
            appliedSaves = saves?.appliedViews().orEmpty(),
            deletedVaults = deletedVaultsRead,
            space = space,
            storage = AccountStorage.of(source.quota()),
            removingLine = if (removing) ContentCopy.REMOVING_LINE else null,
        )
    }

    /** A new state, to the flow and every listener; nothing once closed. */
    internal fun publish() {
        if (closed) return
        val s = build()
        flow.value = s
        for (l in listeners.values.toList()) l(s)
    }

    private fun contentVault(v: VaultView, stopped: Boolean): ContentVault = ContentVault(
        v.vaultId, v.name, v.type == "personal", v.role,
        when {
            stopped -> ContentVaultState.STOPPED
            v.standing == VaultStanding.FROZEN -> ContentVaultState.FROZEN
            v.standing == VaultStanding.FAILED -> ContentVaultState.FAILED
            v.standing == VaultStanding.WITHHELD -> ContentVaultState.WITHHELD
            v.closedFor != null -> ContentVaultState.CLOSED_FOR_WRITING
            v.role == VaultAccess.ROLE_READER || !v.writable -> ContentVaultState.READER
            else -> ContentVaultState.WRITABLE
        },
        v.closedFor,
        v.closedFor?.let(ContentCopy::closedForWriting),
    )

    private fun writable(vaultId: String): Boolean = !source.halted && source.vaults().any { it.vaultId == vaultId && it.writable }

    // ---- the check before a large copy (spec 03 §14.4, design §3.13) ----

    /**
     * The account owns [vaultId] here (its personal vault, or a shared vault it owns): only then does a write into it
     * count against this account's own use, which is all a server tells it. Into another owner's vault the server decides.
     */
    private fun ownedHere(vaultId: String): Boolean =
        source.vaults().any { it.vaultId == vaultId && (it.type == "personal" || it.role == VaultAccess.ROLE_OWNER) }

    /** The policy's limit for one file: what caps a size an item's document declares. */
    private fun fileMax(): Long = limits().perFileBytes

    /** A check with something to say becomes [ContentState.space]; one with nothing (room, unknown) clears it. */
    private fun said(check: SpaceCheck?) {
        space = check?.takeIf { it.verdict == SpaceVerdict.NOT_ENOUGH || it.verdict == SpaceVerdict.NOT_ENOUGH_ON_DECLARED_SIZES }
    }

    /**
     * The check on a fresh sync ([ContentSource.roomFor]): null to go on (room, unknown, or short only on declared
     * sizes, which [ContentState.space] says), else the answer that stops the work before anything is sent: the
     * refusal for space with which limit and by how much, or the sync's own failure.
     */
    private suspend fun freshGate(size: CopySize, forWhat: SpaceFor, vaultId: String): ActionResult? =
        when (val r = source.roomFor(size)) {
            is ItemResult.Failed -> failed(r.why, ContentCopy.During.OTHER)
            is ItemResult.Ok -> {
                val check = SpaceCheck.of(r.value, forWhat, vaultId)
                said(check)
                if (check.verdict == SpaceVerdict.NOT_ENOUGH) ActionResult.Failed(ContentCopy.outOfSpace(check)) else null
            }
        }

    /**
     * Run a person's intent: busy while it runs, a sentence for anything it throws, nothing at all once closed.
     *
     * Once started, an intent runs to its end even when its caller is cancelled ([readOnly] ones excepted): a screen
     * that leaves (its own scope cancelled, as a desktop detail view leaves the moment the item it shows is deleted)
     * must not cut a write short between the engine's queue and the server's answer. Cut there, the write stayed queued
     * unsaid, "changes waiting to send" showed until the next sync, and its notice was never set. A lock still ends an
     * intent: the content is closed and the intent answers nothing.
     *
     * The answer of an intent whose screen has left reaches nobody, so a refusal it carries (a save the server refused,
     * a move that left the item in both vaults, a delete that was denied) becomes the content's [ContentState.notice]:
     * the next screen says it. What went well is said there already, where it needs saying.
     */
    private suspend fun action(readOnly: Boolean = false, block: suspend () -> ActionResult): ActionResult {
        if (closed) return ActionResult.NotDone(null)
        busyCount++
        if (!readOnly) writing.update { it + 1 }
        error = null
        publish()
        val caller = currentCoroutineContext()[Job]
        return try {
            val r = if (readOnly) {
                block()
            } else {
                withContext(NonCancellable) {
                    block().also {
                        // A refusal for good this write's drain met is kept with its kept saves at once ([noteRefusedForGood]).
                        noteRefusedForGood()
                        if (caller?.isActive == false && !closed) leftBehind(it)
                        // The extension fills from what the person just changed, not from the last sync's copy.
                        writeFillSnapshot()
                    }
                }
            }
            if (closed) ActionResult.NotDone(null) else r
        } catch (c: CancellationException) {
            throw c
        } catch (t: Throwable) {
            // Not swallowed: the person is told, in the one neutral sentence (never raw exception text).
            if (closed) {
                ActionResult.NotDone(null)
            } else {
                ActionResult.Failed(ContentCopy.SOMETHING_WENT_WRONG).also { if (!readOnly && caller?.isActive == false) leftBehind(it) }
            }
        } finally {
            busyCount--
            if (!readOnly) writing.update { it - 1 }
            publish()
        }
    }

    /**
     * [block], a write of the item named [name]: when a lock overtook it before this device kept it ([LockedBeforeKept])
     * and nothing else keeps it ([kept]), its name is noted for the next unlock to say. The lock still ends the intent.
     */
    private inline fun <T> notingUnkept(name: String, item: String?, kept: Boolean = false, kind: LockCutKind = LockCutKind.SAVE, block: () -> T): T = try {
        block()
    } catch (e: LockedBeforeKept) {
        if (!kept) {
            if (kind == LockCutKind.SAVE) unsaved.save(name, item) else unsaved.cut(kind, name)
        }
        throw e
    }

    /**
     * [block], one step of a person's change that a lock can cut short: when the lock closed this content before the
     * step finished (its answer is not Ok once the content is closed, or the lock's own exception ends it), [note] is
     * made for the next unlock to say ([UnsavedAtLock.cut]). A step that finished needs no word.
     */
    private inline fun <T> cutting(note: () -> Unit, block: () -> ItemResult<T>): ItemResult<T> {
        val r = try {
            block()
        } catch (e: KeysGoneException) {
            note()
            throw e
        }
        if (closed && r !is ItemResult.Ok) note()
        return r
    }

    /**
     * A write's failure as the person reads it; a refusal for space says whose space it is (the shared vaults' approved
     * lines): this account's for the personal vault and a vault it owns, the owner's otherwise.
     */
    private fun writeFailed(why: ItemFailure, during: ContentCopy.During, vaultId: String?): ActionResult {
        val r = failed(why, during)
        if ((r as? ActionResult.Failed)?.message != ContentCopy.OUT_OF_SPACE) return r
        val home = vaultId ?: source.personalVaultId
        return ActionResult.Failed(ContentCopy.outOfSpaceWhose(home != null && ownedHere(home)))
    }

    /** The answer of a write whose screen has left: a refusal or a "not done" with a sentence is kept as the notice. */
    private fun leftBehind(r: ActionResult) {
        when (r) {
            is ActionResult.Failed -> say(r.message, ContentNoticeKind.REFUSED)
            is ActionResult.NotDone -> r.message?.let { say(it, ContentNoticeKind.REFUSED) }
            else -> Unit
        }
    }

    // ---- the list ----

    override fun setQuery(query: String) {
        this.query = query
        publish()
    }

    /** An item of the live view, or of a vault in the holding area that can still be read (read-only there). */
    private fun findItem(itemId: String): VaultItem? = source.item(itemId)
        ?: source.heldVaults().asSequence().filter { it.readable }.flatMap { source.heldItems(it.vaultId).asSequence() }.firstOrNull { it.itemId == itemId }

    private fun doc(itemId: String): ItemDoc? = if (closed) null else findItem(itemId)?.doc

    override fun itemDetail(itemId: String): ItemDetail? {
        if (closed) return null
        val item = findItem(itemId) ?: return null
        val doc = item.doc
        return ItemDetail(
            itemId = item.itemId, vaultId = item.vaultId, type = doc.type, name = doc.name,
            username = doc.login?.username?.ifEmpty { null }, uris = doc.login?.uris.orEmpty(),
            hasPassword = !doc.login?.password.isNullOrEmpty(), hasNotes = !doc.notes.isNullOrEmpty(),
            hasTotp = !doc.login?.totp.isNullOrEmpty(), favorite = doc.favorite, updatedAt = item.updatedAt,
            editable = doc.type in EDITABLE_TYPES && writable(item.vaultId),
            previousPasswords = minOf(doc.login?.passwordHistory?.size ?: 0, ContentSaves.HISTORY_MAX),
            card = doc.card?.takeIf { doc.type == "card" }?.let { c ->
                CardDetail(
                    summary = CardDisplay.subtitle(doc), cardholder = c.cardholderName?.ifEmpty { null },
                    expiry = listOfNotNull(c.expMonth?.ifEmpty { null }, c.expYear?.ifEmpty { null }).joinToString("/").ifEmpty { null },
                    postalCode = c.postalCode?.ifEmpty { null }, hasNumber = !c.number.isNullOrEmpty(), hasCode = !c.securityCode.isNullOrEmpty(),
                    expMonth = c.expMonth?.ifEmpty { null }, expYear = c.expYear?.ifEmpty { null },
                )
            },
            attachments = doc.attachments.map { AttachmentView(it.id, AttachmentRules.safeFileName(it.name), it.size) },
        )
    }

    override fun revealSecret(itemId: String, field: SecretField): String? {
        val doc = doc(itemId) ?: return null
        return when (field) {
            SecretField.PASSWORD -> doc.login?.password
            SecretField.NOTES -> doc.notes
            SecretField.TOTP_SECRET -> doc.login?.totp
            SecretField.CARD_NUMBER -> doc.card?.number
            SecretField.CARD_CODE -> doc.card?.securityCode
        }?.ifEmpty { null }?.also { used(itemId) }
    }

    /**
     * The newest [ContentSaves.HISTORY_MAX] earlier passwords, newest first: what this app ever keeps. A longer history
     * (another writer's, perhaps hostile) is read no further.
     */
    private fun history(itemId: String) = doc(itemId)?.login?.passwordHistory.orEmpty().takeLast(ContentSaves.HISTORY_MAX).reversed()

    override fun passwordHistory(itemId: String): List<Long> = history(itemId).map { it.retiredAt }

    override fun previousPassword(itemId: String, index: Int): String? =
        history(itemId).getOrNull(index)?.password?.ifEmpty { null }?.also { used(itemId) }

    /** When this unlock last recorded a use of each item ([used]). */
    private val usedAt = HashMap<String, Long>()

    /**
     * A use of [itemId] (spec 02 §8.2), recorded once here for every platform: a login or card released to a fill, or a
     * secret the person revealed or copied. A release of the same item within [USE_WINDOW_MS] of the last recorded one
     * is the same use (a card fill asks for each field; a reveal is often followed by a copy). Health shows it at once;
     * the session batches and sends it ([ContentHost.recordUse]).
     */
    private fun used(itemId: String, atMs: Long? = null) {
        if (closed) return
        val now = wallMs()
        // A pick the platform reports later is recorded at its own time; never after now (the ledger keeps the larger).
        val at = atMs?.coerceAtMost(now) ?: now
        val last = usedAt[itemId]
        if (last != null && (if (at >= last) at - last else last - at) < USE_WINDOW_MS) return
        usedAt[itemId] = if (last == null) at else maxOf(last, at)
        healthPart.used(itemId, at)
        host.recordUse(itemId, at)
    }

    override fun oneTimeCode(itemId: String): OneTimeCode? {
        val uri = doc(itemId)?.login?.totp?.ifEmpty { null } ?: return null
        return try {
            val config = Totp.parseUri(Totp.normalize(uri))
            val nowSeconds = wallMs() / 1000
            val period = config.periodSeconds
            OneTimeCode(Totp.code(crypto, config, nowSeconds), (period - (nowSeconds % period)).toInt(), period)
        } catch (e: Exception) {
            null // a stored key this app cannot read shows no code, as before
        }
    }

    override fun generatePassword(settings: GeneratorSettings): String {
        val options = GeneratorOptions(settings.length, settings.lower, settings.upper, settings.digits, settings.symbols, settings.avoidAmbiguous)
        return try {
            PasswordGenerator.generate(crypto, options)
        } catch (e: Exception) {
            // Settings no password can satisfy (every class off): the standard ones, at the asked length.
            PasswordGenerator.generate(crypto, GeneratorOptions(length = settings.length.coerceIn(8, 128)))
        }
    }

    // ---- the editors ----

    /** An editor's save asked for once a lock closed this content: its screen is going, so the next unlock says it. */
    private fun closedSave(name: String, itemId: String?): ActionResult? {
        if (!closed) return null
        if (name.isNotBlank()) unsaved.save(name, itemId ?: draft?.takeIf { it.itemId == null }?.newItemId)
        return ActionResult.NotDone(null)
    }

    override suspend fun saveLogin(itemId: String?, input: LoginInput, vaultId: String?): ActionResult = closedSave(input.name, itemId) ?: action {
        if (input.name.isBlank()) return@action ActionResult.Failed(ContentCopy.NAME_REQUIRED)
        val totp = if (input.totp.isBlank()) "" else Totp.normalize(input.totp)
        if (totp.isNotEmpty() && runCatching { Totp.parseUri(totp) }.isFailure) return@action ActionResult.Failed(ContentCopy.TOTP_INVALID)
        val existing = itemId?.let { source.item(it) ?: return@action ActionResult.Failed(goneLine(it)) }
        // A copy of the existing document, never a rebuild: favorites, the password history, attachments and fields
        // this client does not know survive the edit (spec 02 §3).
        val base = existing?.doc ?: ItemDoc(type = "login", name = "")
        val doc = base.copy(
            name = input.name.trim(),
            notes = input.notes.ifBlank { null },
            favorite = input.favorite,
            login = (base.login ?: LoginData()).copy(
                username = input.username,
                password = input.password,
                uris = input.uris.map { it.trim() }.filter { it.isNotEmpty() },
                totp = totp.ifEmpty { null },
            ),
        )
        write(itemId, existing, doc, vaultId)
    }

    override suspend fun saveCard(itemId: String?, input: CardInput, vaultId: String?): ActionResult = closedSave(input.name, itemId) ?: action {
        if (input.name.isBlank()) return@action ActionResult.Failed(ContentCopy.CARD_NAME_REQUIRED)
        val combined = if (input.expMonth.isNotBlank() && CardNormalize.padMonth(input.expMonth) == null && input.expYear.isBlank()) CardNormalize.parseExpiry(input.expMonth) else null
        val month = combined?.expMonth ?: CardNormalize.padMonth(input.expMonth)
        val year = combined?.expYear ?: CardNormalize.yearTo4(input.expYear)
        if ((input.expMonth.isNotBlank() && month == null) || (input.expYear.isNotBlank() && year == null)) return@action ActionResult.Failed(ContentCopy.CARD_EXPIRY_INVALID)
        val existing = itemId?.let { source.item(it) ?: return@action ActionResult.Failed(goneLine(it)) }
        if (existing != null && existing.doc.type != "card") return@action ActionResult.Failed(ContentCopy.ITEM_GONE)
        // No card number is longer than 19 digits (ISO/IEC 7812). A number already stored is kept as it is.
        val digits = CardNormalize.digitsOnly(input.number)
        if (digits.length > CARD_NUMBER_MAX_DIGITS && digits != existing?.doc?.card?.number) return@action ActionResult.Failed(ContentCopy.CARD_NUMBER_TOO_LONG)
        val base = existing?.doc ?: ItemDoc(type = "card", name = "", card = CardData())
        val doc = base.copy(
            name = input.name.trim(),
            notes = input.notes.ifBlank { null },
            favorite = input.favorite,
            card = (base.card ?: CardData()).copy(
                cardholderName = input.cardholder.trim().ifBlank { null },
                number = digits.ifBlank { null },
                expMonth = month,
                expYear = year,
                securityCode = CardNormalize.digitsOnly(input.securityCode).ifBlank { null },
                postalCode = input.postalCode.trim().ifBlank { null },
                brand = CardNormalize.brand(input.number),
            ),
        )
        write(itemId, existing, doc, vaultId)
    }

    override fun cardNumberWarning(number: String): String? {
        val digits = CardNormalize.digitsOnly(number)
        return when {
            digits.length > CARD_NUMBER_MAX_DIGITS -> ContentCopy.CARD_NUMBER_TOO_LONG
            digits.length >= 12 && !CardNormalize.luhnValid(digits) -> ContentCopy.CARD_NUMBER_UNUSUAL
            else -> null
        }
    }

    override suspend fun saveNote(itemId: String?, input: NoteInput, vaultId: String?): ActionResult = closedSave(input.name, itemId) ?: action {
        if (input.name.isBlank()) return@action ActionResult.Failed(ContentCopy.NOTE_NAME_REQUIRED)
        val existing = itemId?.let { source.item(it) ?: return@action ActionResult.Failed(goneLine(it)) }
        if (existing != null && existing.doc.type != "note") return@action ActionResult.Failed(ContentCopy.ITEM_GONE)
        val base = existing?.doc ?: ItemDoc(type = "note", name = "")
        write(itemId, existing, base.copy(name = input.name.trim(), notes = input.text.ifBlank { null }, favorite = input.favorite), vaultId)
    }

    /**
     * The one save path of the editors. A new item goes to [vaultId] (a writable vault) or the personal vault; never to
     * a guessed one. An edit is sealed under the vault its editor opened on (INV-EDIT, spec 02 §7.2): [vaultId] when
     * the editor names it, else the vault the item is in now; an item that moved meanwhile is refused, never re-targeted.
     */
    private suspend fun write(itemId: String?, existing: VaultItem?, doc: ItemDoc, vaultId: String?): ActionResult {
        if (source.halted) return ActionResult.Failed(stoppedLine)
        if (existing == null) newHomeRefusal(vaultId)?.let { return it }
        val key = itemId ?: NEW_ITEM
        if (!saving.add(key)) return ActionResult.NotDone(null) // this editor's save runs already
        val d = draft?.takeIf { it.itemId == itemId }
        try {
            val target = if (existing != null) vaultId ?: existing.vaultId else vaultId
            d?.saving = true
            val withFiles = if (d == null) doc else {
                // Files first (spec 02 §6): every new file goes up before the item that names it, under ids minted
                // once, so a retry converges on the uploads that landed.
                val home = target ?: source.personalVaultId ?: return ActionResult.Failed(ContentCopy.NO_PERSONAL_VAULT)
                if (d.uploadedTo != null && d.uploadedTo != home) d.rebind(crypto)
                d.uploadedTo = home
                val id = itemId ?: d.newItemId
                if (d.added.isNotEmpty()) keepSave(d, itemId, existing, doc, home)?.let { return it }
                val pending = d.added.filter { it.id !in d.uploaded }
                var done = d.added.size - pending.size
                if (pending.isNotEmpty()) {
                    upload = UploadView(done, d.added.size)
                    publish()
                }
                for (ref in pending) {
                    // A copy goes to the transport: a lock while it sends wipes the draft's arrays ([close]), and the
                    // server must never hold, under this file's id, bytes that are not the ones sealed.
                    val r = source.uploadEncryptedAttachment(ref.id, id, home, d.sealed.getValue(ref.id).copyOf())
                    if (r is ItemResult.Failed) return writeFailed(r.why, ContentCopy.During.SAVE, home)
                    d.uploaded += ref.id
                    keptFileSentAt[ref.id] = wallMs()
                    upload = UploadView(++done, d.added.size)
                    publish()
                }
                doc.copy(attachments = doc.attachments.filter { it.id !in d.removed } + d.added)
            }
            val draftId = if (itemId == null) d?.newItemId else null
            val pendingBefore = source.pendingSyncItemIds()
            // A save with new files is kept ([keepSave]) and finished after the next unlock; any other is said there.
            var queuedHere = false
            val r = notingUnkept(doc.name, itemId ?: draftId, kept = d?.keptId != null) {
                source.save(itemId, withFiles, target, emptyList(), null, draftId, null) { queuedHere = true }
            }
            // The copy closed for the policy's wipe while this save ran, with its change already in the copy's queue: the
            // policy's one try sends it, so it is not said as "not made" (it may or may not arrive; the notice tells). The
            // engine says whether it queued this save's change at all: one stopped before that is not made, also where
            // the item already had an earlier change waiting (which the item's ids alone cannot tell apart).
            if (r is ItemResult.Failed && r.why == ItemFailure.Halted && host.removingForPolicy() && queuedHere) {
                val now = source.pendingSyncItemIds()
                val id = itemId ?: draftId
                if (if (id != null) id in now else (now - pendingBefore).isNotEmpty()) return ActionResult.Failed(ContentCopy.IN_POLICY_ATTEMPT)
            }
            return when (r) {
                is ItemResult.Ok -> {
                    ContentCopy.kept(r.value.outcome)?.let { say(it, ContentNoticeKind.QUEUED) }
                    if (d != null) {
                        // The server has the item: the kept save and its files go. A change that waits in the durable
                        // queue has not landed: the save stays kept with its files until it has ([KeptSave.queuedAt]).
                        d.keptId?.let { if (r.value.outcome.waits) keepQueued(it) else kept.forget(it) }
                        d.keptId = null
                        d.keptFiles.clear()
                    }
                    if (d != null && draft === d) {
                        // Sent: the encrypted bytes are let go, not zeroed, since a transport may still hold them.
                        d.sealed.clear()
                        draft = null
                    }
                    ActionResult.Ok
                }
                is ItemResult.Failed -> writeFailed(r.why, ContentCopy.During.SAVE, target)
            }
        } finally {
            d?.saving = false
            upload = null
            saving.remove(key)
        }
    }

    /**
     * Keep the editor's save with its new files before anything is sent ([KeptSave]), so one a lock cuts short is
     * finished after the next unlock under the same ids ([resumeKeptSaves]), and a second Save of the same editor
     * replaces it. Each new file is set aside, encrypted as it already is. A failure answers what to say; null: kept.
     */
    private fun keepSave(d: Draft, itemId: String?, existing: VaultItem?, doc: ItemDoc, home: String): ActionResult? {
        for (ref in d.added) {
            if (ref.id in d.keptFiles) continue
            val sealed = d.sealed[ref.id] ?: return ActionResult.Failed(ContentCopy.FILE_NOT_SET_ASIDE)
            if (!kept.putBlob(ref.id, sealed)) return ActionResult.Failed(ContentCopy.FILE_NOT_SET_ASIDE)
            d.keptFiles += ref.id
        }
        val save = KeptSave(
            id = d.keptId ?: freshId(crypto), itemId = itemId, newItemId = itemId ?: d.newItemId, vaultId = home,
            baseRev = existing?.rev ?: 0L, doc = doc.copy(attachments = doc.attachments.filter { it.id !in d.removed } + d.added),
            newFiles = d.added.map { it.id }, removedFiles = d.removed.toList(),
        )
        when (kept.keep(save)) {
            ContentKeptSaves.Kept.KEPT -> Unit
            ContentKeptSaves.Kept.NOT_WRITTEN -> return ActionResult.Failed(ContentCopy.FILE_NOT_SET_ASIDE)
            ContentKeptSaves.Kept.UNREADABLE -> return ActionResult.Failed(ContentCopy.KEPT_SAVES_UNREADABLE)
        }
        d.keptId = save.id
        // Files an earlier try of this editor's save set aside and this one does not name (a vault changed: new ids).
        d.keptFiles.filter { it !in save.newFiles }.forEach {
            kept.dropBlob(it)
            d.keptFiles.remove(it)
        }
        return null
    }

    /** How finishing a kept save came out. */
    private sealed class KeptEnd {
        /**
         * Sent: only its new files went onto the item as it is now ([filesOnly]), and whether files it took off stayed.
         * [outcome] says whether the item's change reached the server or was kept in the durable queue to be sent later.
         */
        class Finished(val filesOnly: Boolean, val removalsNotKept: Boolean, val outcome: Written) : KeptEnd()

        class Failed(val why: ItemFailure) : KeptEnd()

        /** A file set aside for it is no longer on this device (or its record names a file it does not hold): it can never be sent as made. */
        data object FileMissing : KeptEnd()
    }

    /** The item's row as the server last served it to this device (never a change of it that waits in the queue). */
    private fun serverRow(itemId: String): SyncItem? = source.envelopes().firstOrNull { it.itemId == itemId }

    /**
     * The server has the item as [p] saves it: the item as the server holds it names every new file of it. A change that
     * only waits in the queue is not landed (the queue shows it, but the server may still refuse it).
     */
    private fun landed(p: KeptSave): Boolean = serverRow(p.newItemId)?.takeIf { !it.deleted }?.attachmentIds?.containsAll(p.newFiles) == true

    /**
     * A save whose change was handed to the durable queue ([KeptSave.queuedAt]) has landed: nothing of the item waits in
     * the queue any more, and the server holds it at a newer revision than when the change was queued (a later edit of the
     * person that took one of its files off counts: the item landed, as the person left it).
     */
    private fun queuedLanded(p: KeptSave, pending: Set<String>): Boolean {
        val at = p.queuedAt ?: return false
        if (p.newItemId in pending) return false
        val row = serverRow(p.newItemId) ?: return false
        return row.rev > at
    }

    /** The kept save [id]'s change was handed to the durable queue: it stays kept, with its files, until it has landed. */
    private fun keepQueued(id: String) {
        val p = (kept.load() as? KeptRead.Read)?.value?.firstOrNull { it.id == id } ?: return
        // Not written: it stays kept as it was, and is judged by its files ([landed]); nothing is lost either way.
        kept.keep(p.queued(serverRow(p.newItemId)?.rev ?: 0L))
    }

    /**
     * Before a drain of the queue ([io.silencelen.andvari.core.client.items.BeforeDrain]): the files of each kept save whose
     * change waits in it go up again, unless this unlock sent them a short while ago; the server removes an upload no
     * item names after a day, and would then refuse the change that names it. Uploading again what it still holds changes
     * nothing (the same id and bytes). A failure the drain would meet too stops it; any other is the change's to meet.
     */
    private suspend fun filesBeforeDrain(waitingPuts: Set<String>): ItemFailure? {
        if (closed) return null
        val all = (kept.load() as? KeptRead.Read)?.value ?: return null
        for (p in all) {
            if (p.newItemId !in waitingPuts || p.newFiles.isEmpty() || landed(p)) continue
            for (id in p.newFiles) {
                val now = wallMs()
                val at = keptFileSentAt[id]
                if (at != null && now >= at && now - at < KEPT_FILE_RESEND_AFTER_MS) continue
                val sealed = (kept.blob(id) as? KeptRead.Read)?.value ?: continue
                when (val r = source.uploadEncryptedAttachment(id, p.newItemId, p.vaultId, sealed)) {
                    is ItemResult.Ok -> keptFileSentAt[id] = now
                    is ItemResult.Failed -> if (Written.keptFor(r.why) != null) return r.why
                }
                if (closed) return null
            }
        }
        return null
    }

    /**
     * After a sync (and before the kept saves are judged): a kept save whose change was handed to the queue, and which the
     * server then refused for good when a drain sent it ([ContentSource.takeRefusedForGood], judged as [givenUp] judges a
     * refusal), is let go with its files once, and said with the line that names what was lost. Never one whose item
     * still has a change waiting, or that the server holds with its files (a later change of it landed). A refusal of a
     * file the server no longer holds is not one of them: the files set aside here go up again when it is finished afresh.
     */
    private fun giveUpRefusedKeptSaves() {
        refusalSaid = false
        if (closed) return
        noteRefusedForGood()
        val all = (kept.load() as? KeptRead.Read)?.value ?: return
        if (all.none { it.refusal != null }) return
        val pending = source.pendingSyncItemIds()
        for (p in all) {
            val why = p.refusal?.failure() ?: continue
            // Not judged yet while its editor is open or a change of its item waits (a later save of the same item): the
            // refusal stays with its record, across a lock or a restart, until the save can be judged by it.
            if (draft?.keptId == p.id || p.newItemId in pending) continue
            val kept = landed(p) || !givenUp(why) ||
                (why is ItemFailure.Refused && why.code == io.silencelen.andvari.core.model.wire.WireErrors.UNKNOWN_ATTACHMENT)
            if (kept) {
                this.kept.keep(p.judged())
                continue
            }
            this.kept.forget(p.id)
            say(ContentCopy.keptSaveGivenUp(p.doc.name.ifBlank { "An item" }, p.itemId == null, p.newFiles.size, ContentCopy.forFailure(why, ContentCopy.During.SAVE)), ContentNoticeKind.KEPT_SAVE)
            refusalSaid = true
        }
    }

    /**
     * The refusals for good the engine holds ([ContentSource.takeRefusedForGood]) are taken, after every write and every
     * sync, and each is written with the record of every kept save of its item whose change waited in the queue then
     * ([KeptSave.refusal]), so that a lock or a restart before the save is judged loses nothing. A refusal stays in this
     * content's memory ([refusedUnjudged]) while the records cannot be read or written, and is written at the next chance;
     * one whose item has no such kept save goes. A kept save of the item made after the refusal was taken is not judged
     * by it. One that was already waiting when it was taken is, even where the refused change was not its own: a later
     * save whose change landed, from which a later edit took its own file off before the next sync, is then said as given
     * up rather than going silently (on the safe side).
     */
    private fun noteRefusedForGood() {
        if (closed) return
        refusedUnjudged.putAll(source.takeRefusedForGood())
        if (refusedUnjudged.isEmpty()) return
        val all = (kept.load() as? KeptRead.Read)?.value ?: return
        for (p in all) {
            if (p.queuedAt == null) continue
            val marked = refusedUnjudged[p.newItemId]?.let(p::refusedWith) ?: continue
            if (kept.keep(marked) != ContentKeptSaves.Kept.KEPT) return
        }
        refusedUnjudged.clear()
    }

    /** Refusals for good taken from the engine and not yet written with their kept saves ([noteRefusedForGood]). */
    private val refusedUnjudged = LinkedHashMap<String, ItemFailure>()

    /** This sync's [giveUpRefusedKeptSaves] said a kept save given up: a line that a save is done does not cover it. */
    private var refusalSaid = false

    /** After a sync: a kept save whose queued change has landed goes, with its files ([queuedLanded]). */
    private fun settleQueuedKeptSaves() {
        if (closed) return
        val all = (kept.load() as? KeptRead.Read)?.value ?: return
        if (all.none { it.queuedAt != null }) return
        val pending = source.pendingSyncItemIds()
        for (p in all) if (draft?.keptId != p.id && queuedLanded(p, pending)) kept.forget(p.id)
    }

    /** The person deleted [itemId]: a save kept for it is let go with its files, and never brings the item back. */
    private fun keptItemDeleted(itemId: String) {
        val all = (kept.load() as? KeptRead.Read)?.value ?: return
        for (p in all) if (p.newItemId == itemId && draft?.keptId != p.id) kept.forget(p.id)
    }

    /**
     * Finish a save a lock cut short, after a sync: its new files go up under their ids, then the item. A save older than
     * what happened since (the item's revision moved, or an edit of it waits to be sent: round-10 review 5) adds only its
     * new files to the item as it is now; nothing else of it is applied, the files it took off included.
     */
    private suspend fun finishKept(p: KeptSave): KeptEnd {
        val refs = p.doc.attachments.associateBy { it.id }
        if (!landed(p)) {
            for (id in p.newFiles) {
                if (refs[id] == null) return KeptEnd.FileMissing
                val sealed = when (val b = kept.blob(id)) {
                    is KeptRead.Read -> b.value ?: return KeptEnd.FileMissing
                    // A file that could not be read now is not a file gone: the save waits (never given up for it).
                    KeptRead.Locked, KeptRead.Unreadable -> return KeptEnd.Failed(ItemFailure.Unreachable(NoAnswerKind.TRANSPORT))
                }
                // Let go, not zeroed, once sent: it is encrypted, and a transport may still hold it.
                val r = source.uploadEncryptedAttachment(id, p.newItemId, p.vaultId, sealed)
                if (r is ItemResult.Failed) return KeptEnd.Failed(r.why)
                keptFileSentAt[id] = wallMs()
                if (closed) return KeptEnd.Failed(ItemFailure.Unreachable(NoAnswerKind.TRANSPORT))
            }
        }
        if (landed(p)) return KeptEnd.Finished(filesOnly = false, removalsNotKept = false, outcome = Written.APPLIED)
        val current = p.itemId?.let { source.item(it) }
        val waiting = p.itemId != null && p.itemId in source.pendingSyncItemIds()
        return if (current != null && (current.rev != p.baseRev || waiting)) {
            val added = p.doc.attachments.filter { it.id in p.newFiles }
            val files = current.doc.attachments.filter { it.id !in p.newFiles } + added
            val removalsNotKept = current.doc.attachments.any { it.id in p.removedFiles }
            when (val r = source.save(p.itemId, current.doc.copy(attachments = files), p.vaultId, emptyList(), null, null, null)) {
                is ItemResult.Ok -> KeptEnd.Finished(filesOnly = true, removalsNotKept = removalsNotKept, outcome = r.value.outcome)
                is ItemResult.Failed -> KeptEnd.Failed(r.why)
            }
        } else {
            val r = source.save(p.itemId, p.doc, p.vaultId, emptyList(), null, if (p.itemId == null) p.newItemId else null, if (p.itemId != null && !waiting) p.baseRev else null)
            when (r) {
                is ItemResult.Ok -> KeptEnd.Finished(filesOnly = false, removalsNotKept = false, outcome = r.value.outcome)
                is ItemResult.Failed -> KeptEnd.Failed(r.why)
            }
        }
    }

    /**
     * After this unlock's first sync: the saves with files a lock cut short are finished under the ids they were given.
     * One the server refuses for good is let go and said; one that still cannot get through stays for the next unlock.
     * Files set aside for an editor the app was closed in go. Nothing is decided while the account is locked.
     */
    private suspend fun resumeKeptSaves() {
        if (keptResumed || closed) return
        keptResumed = true
        val all = when (val r = kept.load()) {
            is KeptRead.Read -> r.value
            KeptRead.Locked -> return
            KeptRead.Unreadable -> {
                // Unknown, never empty: nothing is finished, forgotten or swept; the next sync reads again.
                keptResumed = false
                say(ContentCopy.KEPT_SAVES_UNREADABLE, ContentNoticeKind.RECORDS)
                return
            }
        }
        kept.sweep(draft?.added?.mapTo(HashSet()) { it.id }.orEmpty())
        if (all.isEmpty() || source.halted) return
        var done = 0
        var filesOnly: Pair<String, Boolean>? = null
        for (p in all) {
            if (closed) return
            if (draft?.keptId == p.id) continue // its editor is open: its own Save finishes it
            val name = p.doc.name.ifBlank { "An item" }
            if (p.queuedAt != null) {
                val pending = source.pendingSyncItemIds()
                if (queuedLanded(p, pending)) {
                    // Its change waited in the queue and has landed now: the save is done.
                    kept.forget(p.id)
                    done++
                    continue
                }
                if (p.newItemId in pending) {
                    // Still waiting (a vault this device cannot send to now): kept, with its files, for a later sync.
                    say(ContentCopy.savedLater(name), ContentNoticeKind.KEPT_SAVE)
                    continue
                }
                // Nothing of it waits any more, and the server does not hold it: finished afresh, as kept.
            }
            when (val r = finishKept(p)) {
                is KeptEnd.Finished -> {
                    if (closed) return
                    val waits = ContentCopy.kept(r.outcome)
                    if (waits != null) {
                        // Its files are on the server and its change waits in the durable queue: not "done". The save
                        // stays kept with its files until the item has landed, and the line says when it goes.
                        kept.keep(p.queued(serverRow(p.newItemId)?.rev ?: 0L))
                        say(waits, ContentNoticeKind.KEPT_SAVE)
                    } else {
                        kept.forget(p.id)
                        if (r.filesOnly && filesOnly == null) filesOnly = name to r.removalsNotKept
                        done++
                    }
                }
                KeptEnd.FileMissing -> {
                    if (closed) return
                    kept.forget(p.id)
                    say(ContentCopy.keptSaveGivenUp(name, p.itemId == null, p.newFiles.size, ContentCopy.KEPT_FILE_NOT_ON_DEVICE), ContentNoticeKind.KEPT_SAVE)
                }
                is KeptEnd.Failed -> {
                    if (closed) return
                    if (givenUp(r.why)) {
                        kept.forget(p.id)
                        say(ContentCopy.keptSaveGivenUp(name, p.itemId == null, p.newFiles.size, ContentCopy.forFailure(r.why, ContentCopy.During.SAVE)), ContentNoticeKind.KEPT_SAVE)
                    } else {
                        say(ContentCopy.savedLater(name, r.why), ContentNoticeKind.KEPT_SAVE)
                    }
                }
            }
        }
        // A save let go by a refusal at this same sync stays said: "done" never covers a save that was lost.
        if (done > 0 && !refusalSaid) {
            val f = filesOnly
            say(
                when {
                    f != null -> ContentCopy.filesOnly(f.first, f.second)
                    done == 1 -> ContentCopy.KEPT_SAVE_DONE
                    else -> "$done ${ContentCopy.KEPT_SAVES_DONE}"
                },
                ContentNoticeKind.KEPT_SAVE,
            )
        }
    }

    /**
     * A failure no later try gets past: the server refused the change itself for good, or what the save needs is gone.
     * Never an answer that passes: the session the server ended (`401`: the account's next session finishes it, as the
     * older controller does), a request that timed out (`408`), too many requests (`429`), a fault of the server, no
     * answer, or a vault closed for writing while a change of it waits (the mark is cleared when that change settles,
     * and a vault that is then gone refuses as not open).
     */
    private fun givenUp(why: ItemFailure): Boolean = when (why) {
        is ItemFailure.NotAllowed -> why.reason != ItemRefusal.VAULT_CLOSED_FOR_WRITING
        is ItemFailure.Denied, is ItemFailure.Corrupt -> true
        // [Written.keptFor] names the refusals for now (the session's end, too many requests, a fault of the server).
        is ItemFailure.Refused -> Written.keptFor(why) == null && why.status in 400..499 && why.status != 408
        else -> false
    }

    /**
     * The files of the item an editor has open: the kept files it takes off, and the files it adds, each encrypted
     * under a key of its own as it is added (its plaintext zeroed then) and held, encrypted, in memory until the save.
     * A new item's id is minted when its editor opens, so every try of its save uses it. It lives while the editor is
     * open, never across a lock.
     */
    private class Draft(val itemId: String?, val newItemId: String) {
        val removed = LinkedHashSet<String>()
        val added = ArrayList<AttachmentRef>()
        val sealed = HashMap<String, ByteArray>()
        val uploaded = HashSet<String>()

        /** The save this editor kept and has not finished ([KeptSave.id]), and the files set aside for it. */
        var keptId: String? = null
        val keptFiles = LinkedHashSet<String>()

        /** The vault the uploads went to; a save into another vault sends them again under fresh ids. */
        var uploadedTo: String? = null
        var saving = false

        fun rebind(crypto: CryptoProvider) {
            for (i in added.indices) {
                val old = added[i]
                val fresh = freshId(crypto)
                sealed[fresh] = sealed.remove(old.id)!!
                added[i] = old.copy(id = fresh)
            }
            uploaded.clear()
        }

        fun wipe() {
            sealed.values.forEach { it.fill(0) }
            sealed.clear()
        }
    }

    // ---- attachments ----

    override fun attachmentLimits(): AttachmentLimitsView = limits()

    private fun keptFiles(d: Draft): List<AttachmentRef> = d.itemId?.let { source.item(it)?.doc?.attachments }.orEmpty().filter { it.id !in d.removed }

    private fun draftView(d: Draft): AttachmentDraftView {
        val kept = keptFiles(d)
        return AttachmentDraftView(
            kept = kept.map(::attachmentView),
            added = d.added.map(::attachmentView),
            totalBytes = kept.sumOf { it.size } + d.added.sumOf { it.size },
            limits = limits(),
        )
    }

    private fun attachmentView(ref: AttachmentRef) = AttachmentView(ref.id, AttachmentRules.safeFileName(ref.name), ref.size)

    override fun openAttachmentDraft(itemId: String?) {
        if (closed) return
        draft?.takeIf { !it.saving }?.let(::giveUp)
        draft = Draft(itemId, itemId ?: freshId(crypto))
        publish()
    }

    override fun closeAttachmentDraft() {
        // A save that runs keeps its files until it is done; it wipes nothing it still needs.
        draft?.takeIf { !it.saving }?.let(::giveUp)
        draft = null
        publish()
    }

    /**
     * The person closed an editor: a save of it that did not finish is given up (the editor is where it is tried
     * again), with the files set aside for it. Only a lock keeps it, for the next unlock.
     */
    private fun giveUp(d: Draft) {
        // A kept save that could not be forgotten (its record unreadable now) keeps its files: a record must never name
        // files that are gone, and the next unlock finishes it as kept.
        val forgotten = d.keptId?.let(kept::forget) ?: true
        if (forgotten) d.keptFiles.forEach(kept::dropBlob)
        d.keptId = null
        d.keptFiles.clear()
        d.wipe()
    }

    override suspend fun addAttachment(name: String, bytes: ByteArray): ActionResult {
        try {
            return action {
                val d = draft?.takeIf { !it.saving } ?: return@action ActionResult.NotDone(null)
                val held = keptFiles(d).sumOf { it.size } + d.added.sumOf { it.size }
                AttachmentRules.refusal(bytes.size.toLong(), held, limits())?.let { return@action ActionResult.Failed(it) }
                val key = crypto.randomBytes(32)
                val sealed = try {
                    withContext(Dispatchers.Default) { Attachments.encrypt(crypto, key, bytes).let { it.header + it.ciphertext } }
                } catch (e: CancellationException) {
                    key.fill(0)
                    throw e
                } catch (e: Exception) {
                    key.fill(0)
                    return@action ActionResult.Failed(ContentCopy.FILE_READ_FAILED)
                }
                val ref = AttachmentRef(id = freshId(crypto), name = AttachmentRules.safeFileName(name), size = bytes.size.toLong(), fileKey = Bytes.toB64(key))
                key.fill(0)
                if (closed || draft !== d || d.saving) {
                    // A lock took the editor while the file was being added: the next unlock says it was not.
                    if (closed) unsaved.cut(LockCutKind.FILE, ref.name)
                    sealed.fill(0)
                    return@action ActionResult.NotDone(null) // closed, or the editor closed, meanwhile
                }
                d.sealed[ref.id] = sealed
                d.added += ref
                ActionResult.Ok
            }
        } finally {
            bytes.fill(0)
        }
    }

    override fun removeAttachment(attachmentId: String) {
        val d = draft?.takeIf { !it.saving } ?: return
        val added = d.added.firstOrNull { it.id == attachmentId }
        if (added != null) {
            d.added.remove(added)
            d.sealed.remove(attachmentId)?.fill(0)
            d.uploaded.remove(attachmentId)
        } else if (keptFiles(d).any { it.id == attachmentId }) {
            d.removed += attachmentId
        }
        publish()
    }

    override suspend fun readAttachment(itemId: String, attachmentId: String): AttachmentContent {
        if (closed) return AttachmentContent("", null, null)
        val ref = source.item(itemId)?.doc?.attachments?.firstOrNull { it.id == attachmentId }
            ?: return AttachmentContent("", null, ContentCopy.FILE_GONE)
        val name = AttachmentRules.safeFileName(ref.name)
        if (ref.size > AttachmentRules.MAX_FILE_BYTES) return AttachmentContent(name, null, ContentCopy.FILE_TOO_LARGE_TO_OPEN)
        return try {
            when (val r = source.downloadAttachment(ref)) {
                is ItemResult.Ok -> if (closed) {
                    r.value.fill(0)
                    AttachmentContent(name, null, null)
                } else AttachmentContent(name, r.value, null)
                is ItemResult.Failed -> AttachmentContent(name, null, if (closed) null else ContentCopy.forFailure(r.why, ContentCopy.During.OTHER))
            }
        } catch (c: CancellationException) {
            throw c
        } catch (t: Throwable) {
            AttachmentContent(name, null, if (closed) null else ContentCopy.SOMETHING_WENT_WRONG)
        }
    }

    // ---- the trash ----

    /** A line about [doc] that tells it apart and is never a secret: a login's username, a card's brand and last four. */
    private fun safeDetail(doc: ItemDoc): String? = when (doc.type) {
        "login" -> doc.login?.username?.ifEmpty { null }
        "card" -> CardDisplay.subtitle(doc).ifEmpty { null }
        else -> null
    }

    private fun trashViews(read: Map<String, DeletedItemView>): List<TrashItemView> = read.values.sortedByDescending { it.deletedAt }.map { d ->
        val doc = d.doc
        TrashItemView(
            itemId = d.itemId, name = doc?.name, type = doc?.type, detail = doc?.let(::safeDetail), vault = vaultName(d.vaultId),
            deletedAtMs = d.deletedAt, canRestore = (doc != null || d.notRead) && writable(d.vaultId), canPurge = writable(d.vaultId),
            notReadYet = doc == null && d.notRead,
        )
    }

    /**
     * The names of the items restored or deleted for good in this session, for the check's sentence when the trash's
     * read cannot name one. Memory only: the kept record ([ContentSource.recordTrashAction]) holds no name.
     */
    private val trashDoneNames = HashMap<String, String?>()

    /**
     * [read] is a whole read of the trash. Each restore or delete for good the server answered as done since the last
     * whole read (kept where the account's data is kept, so a lock between does not lose it) is checked once against
     * it. An item it lists again is said, and the server is named only when this device can tell that its own action
     * was never stored: the trash lists the very deletion the device acted on (the same deletion time) and, for a
     * restore, the device was never served the item live again. Otherwise another device or member deleted it again
     * after the action, and the sentence says only that it is in the trash again.
     */
    private fun checkTrashDone(read: Map<String, DeletedItemView>) {
        val done = source.trashActionsDone()
        if (done.isEmpty()) return
        source.clearTrashActionsDone()
        val notStored = ArrayList<Pair<Boolean, String?>>()
        val again = ArrayList<String?>()
        for (d in done) {
            val row = read[d.itemId] ?: continue
            val name = row.doc?.name ?: trashDoneNames[d.itemId]
            if (row.deletedAt == d.deletedAt && !d.seenLive) notStored += d.restored to name else again += name
        }
        trashDoneNames.clear()
        val lines = listOfNotNull(
            notStored.takeIf { it.isNotEmpty() }?.let(ContentCopy::trashNotDone),
            again.takeIf { it.isNotEmpty() }?.let(ContentCopy::trashInAgain),
        )
        if (lines.isEmpty()) return
        say(lines.joinToString(" "), if (notStored.isNotEmpty()) ContentNoticeKind.NOT_DONE_ON_SERVER else ContentNoticeKind.IN_TRASH_AGAIN)
    }

    /** Keep [itemId]'s restore or delete for good, answered as done, for the next whole read of the trash. */
    private fun recordTrashDone(itemId: String, restored: Boolean, deleted: DeletedItemView, name: String?) {
        trashDoneNames[itemId] = name
        // After a restore the engine syncs at once: a restore the server stored is served live right then.
        val seenLive = restored && source.item(itemId) != null
        source.recordTrashAction(TrashActionDone(itemId, restored, deleted.deletedAt, seenLive))
    }

    override suspend fun openTrash(): ActionResult = action(readOnly = true) {
        val token = ++trashToken
        when (val r = source.deletedItems()) {
            is ItemResult.Ok -> {
                if (token != trashToken) return@action ActionResult.NotDone(null) // closed or opened again meanwhile
                val read = r.value.associateBy { it.itemId }
                trashRead = read
                checkTrashDone(read)
                ActionResult.Ok
            }
            is ItemResult.Failed -> failed(r.why, ContentCopy.During.OTHER)
        }
    }

    override fun closeTrash() {
        trashToken++
        trashRead = null
        publish()
    }

    override suspend fun restoreFromTrash(itemId: String): ActionResult = action {
        val deleted = trashRead?.get(itemId) ?: return@action ActionResult.Failed(ContentCopy.TRASH_GONE)
        if (source.halted) return@action ActionResult.Failed(stoppedLine)
        if (!writable(deleted.vaultId)) return@action ActionResult.Failed(readOnlyLine(deleted.vaultId))
        // A row the trash's opening did not read is read now, on its own (one call), and the row says what it found.
        val doc = deleted.doc ?: if (!deleted.notRead) {
            return@action ActionResult.Failed(ContentCopy.TRASH_UNREADABLE)
        } else {
            when (val r = source.deletedItemDoc(deleted)) {
                is ItemResult.Ok -> {
                    trashRead = trashRead?.let { it + (itemId to deleted.copy(doc = r.value, notRead = false)) }
                    r.value ?: return@action ActionResult.Failed(ContentCopy.TRASH_UNREADABLE)
                }
                is ItemResult.Failed -> return@action failed(r.why, ContentCopy.During.OTHER)
            }
        }
        if (closed) return@action ActionResult.NotDone(null)
        when (val r = cutting({ unsaved.cut(LockCutKind.RESTORE, doc.name) }) { source.restoreDeleted(itemId, deleted.vaultId, doc) }) {
            is ItemResult.Ok -> {
                trashRead = trashRead?.minus(itemId)
                recordTrashDone(itemId, restored = true, deleted, doc.name)
                say(ContentCopy.TRASH_RESTORED, ContentNoticeKind.DONE)
                ActionResult.Ok
            }
            is ItemResult.Failed -> writeFailed(r.why, ContentCopy.During.OTHER, deleted.vaultId)
        }
    }

    override suspend fun purgeFromTrash(itemId: String): ActionResult = action {
        val deleted = trashRead?.get(itemId) ?: return@action ActionResult.Failed(ContentCopy.TRASH_GONE)
        if (source.halted) return@action ActionResult.Failed(stoppedLine)
        if (!writable(deleted.vaultId)) return@action ActionResult.Failed(readOnlyLine(deleted.vaultId))
        when (val r = source.purgeDeleted(itemId, deleted.vaultId)) {
            is ItemResult.Ok -> {
                trashRead = trashRead?.minus(itemId)
                recordTrashDone(itemId, restored = false, deleted, deleted.doc?.name)
                say(ContentCopy.TRASH_PURGED, ContentNoticeKind.DONE)
                ActionResult.Ok
            }
            is ItemResult.Failed -> failed(r.why, ContentCopy.During.OTHER)
        }
    }

    // ---- the owner's "Recently deleted" shared vaults ----

    override suspend fun openDeletedVaults(): ActionResult = action(readOnly = true) {
        val token = ++deletedVaultsToken
        when (val r = source.deletedVaults()) {
            is ItemResult.Ok -> {
                if (token != deletedVaultsToken) return@action ActionResult.NotDone(null)
                // Only what this device's verified log shows deleted by its owner: a served row alone lists nothing.
                deletedVaultsRead = r.value.filter { it.verified }.map {
                    // The day only where the server served one; the row's mark is the vault's own (the verified log).
                    io.silencelen.andvari.core.app.DeletedVaultView(it.vaultId, it.name ?: ContentCopy.DELETED_VAULT_UNNAMED, it.deletedAt, it.purgeAt.coerceAtLeast(0L), deleted = it.verified)
                }
                ActionResult.Ok
            }
            is ItemResult.Failed -> failed(r.why, ContentCopy.During.OTHER)
        }
    }

    override fun closeDeletedVaults() {
        deletedVaultsToken++
        deletedVaultsRead = null
        publish()
    }

    // ---- an item's history ----

    private fun historyView(itemId: String, versions: List<DecryptedItemVersion>): ItemHistoryView {
        val vaultId = source.item(itemId)?.vaultId
        return ItemHistoryView(
            itemId = itemId,
            versions = versions.map { v -> ItemVersionView(v.rev, v.archivedAt, v.doc.name, safeDetail(v.doc), !v.doc.login?.password.isNullOrEmpty()) },
            canRestore = vaultId != null && writable(vaultId),
        )
    }

    override suspend fun openItemHistory(itemId: String): ActionResult = action(readOnly = true) {
        val item = source.item(itemId) ?: return@action ActionResult.Failed(ContentCopy.ITEM_GONE)
        val token = ++historyToken
        when (val r = source.itemVersions(itemId, item.vaultId)) {
            is ItemResult.Ok -> {
                if (token != historyToken) return@action ActionResult.NotDone(null)
                historyRead = itemId to r.value
                ActionResult.Ok
            }
            is ItemResult.Failed -> failed(r.why, ContentCopy.During.OTHER)
        }
    }

    override fun closeItemHistory() {
        historyToken++
        historyRead = null
        publish()
    }

    override fun historyPassword(itemId: String, rev: Long): String? =
        historyRead?.takeIf { it.first == itemId }?.second?.firstOrNull { it.rev == rev }?.doc?.login?.password?.ifEmpty { null }

    override suspend fun restoreItemVersion(itemId: String, rev: Long): ActionResult = action {
        val version = historyRead?.takeIf { it.first == itemId }?.second?.firstOrNull { it.rev == rev }
            ?: return@action ActionResult.Failed(ContentCopy.HISTORY_GONE)
        val item = source.item(itemId) ?: return@action ActionResult.Failed(ContentCopy.ITEM_GONE)
        if (source.halted) return@action ActionResult.Failed(stoppedLine)
        if (!writable(item.vaultId)) return@action ActionResult.Failed(readOnlyLine(item.vaultId))
        // An item's kind never changes: a version of another kind is not this item's.
        if (version.doc.type != item.doc.type) return@action ActionResult.Failed(ContentCopy.HISTORY_GONE)
        val doc = source.versionDocForRestore(itemId, version.doc)
        val token = historyToken
        when (val r = notingUnkept(item.doc.name, itemId, kind = LockCutKind.VERSION) { source.save(itemId, doc, item.vaultId, emptyList(), null, null, null) }) {
            is ItemResult.Ok ->
                say(ContentCopy.kept(r.value.outcome) ?: ContentCopy.VERSION_RESTORED, if (r.value.outcome.waits) ContentNoticeKind.QUEUED else ContentNoticeKind.DONE)
            is ItemResult.Failed -> return@action writeFailed(r.why, ContentCopy.During.SAVE, item.vaultId)
        }
        // The history again, best effort: the version just replaced is in it once the server has the restore.
        val fresh = (source.itemVersions(itemId, item.vaultId) as? ItemResult.Ok)?.value
        if (fresh != null && token == historyToken && historyRead?.first == itemId) historyRead = itemId to fresh
        ActionResult.Ok
    }

    /** Why a new item cannot go to [vaultId] (null: the personal vault), or null when it can. */
    private fun newHomeRefusal(vaultId: String?): ActionResult? = when {
        vaultId != null -> if (writable(vaultId)) null else ActionResult.Failed(notWritableTarget(vaultId))
        // A new item never goes to a guessed vault (design §5.3: no personal vault, no default destination).
        source.personalVaultId == null -> ActionResult.Failed(ContentCopy.NO_PERSONAL_VAULT)
        else -> null
    }

    override suspend fun deleteItem(itemId: String): ActionResult = action {
        if (source.halted) return@action ActionResult.Failed(stoppedLine)
        val existing = source.item(itemId) ?: return@action ActionResult.Failed(goneLine(itemId))
        if (!writable(existing.vaultId)) return@action ActionResult.Failed(readOnlyLine(existing.vaultId))
        when (val r = cutting({ unsaved.cut(LockCutKind.ITEM_DELETE, existing.doc.name) }) { source.remove(itemId) }) {
            is ItemResult.Ok -> {
                ContentCopy.kept(r.value)?.let { say(it, ContentNoticeKind.QUEUED) }
                // A save from the queue that added it has nothing left to undo, and never adds it again.
                saves?.itemDeleted(itemId)
                keptItemDeleted(itemId)
                ActionResult.Ok
            }
            is ItemResult.Failed -> failed(r.why, ContentCopy.During.SAVE)
        }
    }

    // ---- AutoFill ----

    /**
     * The working set's rule: which standings of a vault are filled from. A frozen, failed or withheld vault is not: its
     * items are read, never offered for filling in nor released to a fill. A withheld vault's key is held on every device
     * of the account when the account's record of it stands above the served log (decided on 23 November 2026), and the
     * older log a server serves then can carry rows of a member a later entry removed.
     */
    private fun fillsFrom(standing: VaultStanding): Boolean =
        standing != VaultStanding.FROZEN && standing != VaultStanding.FAILED && standing != VaultStanding.WITHHELD

    /** A vault of [ContentState.vaults] whose standing is filled from ([fillsFrom]). */
    private fun offered(vaultId: String): Boolean = source.vaults().any { it.vaultId == vaultId && fillsFrom(it.standing) }

    private fun workingSet(): List<VaultItem> {
        if (closed) return emptyList()
        val ok = source.vaults().filter { fillsFrom(it.standing) }.mapTo(HashSet()) { it.vaultId }
        return source.items().filter { it.vaultId in ok }
    }

    private fun fillItem(itemId: String): VaultItem? = if (closed) null else source.item(itemId)?.takeIf { offered(it.vaultId) }

    override fun fillLogins(hosts: List<String>): List<FillLogin> = FillRules.logins(workingSet(), hosts)

    override fun fillMatches(itemId: String, identifiers: List<String>): Boolean = FillRules.matches(fillItem(itemId), identifiers)

    override fun fillCredential(itemId: String): FillCredential? = FillRules.credential(fillItem(itemId))?.also { used(itemId) }

    override fun fillCards(): List<FillCard> = FillRules.cards(workingSet())

    override fun fillCardField(itemId: String, field: String): String? = FillRules.cardField(fillItem(itemId), field)?.also { used(itemId) }

    override fun fillCredentialUnrecorded(itemId: String): FillCredential? = FillRules.credential(fillItem(itemId))

    override fun fillCardFieldUnrecorded(itemId: String, field: String): String? = FillRules.cardField(fillItem(itemId), field)

    override fun recordFillPicked(itemId: String): Boolean {
        val item = fillItem(itemId) ?: return false
        if (FillRules.credential(item) == null && item.doc.card == null) return false
        used(itemId)
        return true
    }

    override fun markVaultClosedForWriting(vaultId: String, reason: VaultClosedReason?) {
        if (closed || !TrustGrammar.isUuid(vaultId)) return
        source.markClosedForWriting(vaultId, reason)
        publish()
    }

    /** The line for a change refused because [vaultId] cannot be written here: why it is closed, or read-only. */
    private fun readOnlyLine(vaultId: String): String =
        if (source.vaultDeleted(vaultId)) ContentCopy.VAULT_DELETED_READ_ONLY
        else source.closedForWriting(vaultId)?.let(ContentCopy::closedForWriting) ?: ContentCopy.READ_ONLY

    /**
     * Why an item that is not among the vault's items cannot be changed: one held from a vault whose deletion stands (it
     * is still here, read-only, until the vault is restored or purged) says so; anything else is gone.
     */
    private fun goneLine(itemId: String): String =
        if (source.heldVaults().any { h -> source.vaultDeleted(h.vaultId) && source.heldItems(h.vaultId).any { it.itemId == itemId } }) {
            ContentCopy.VAULT_DELETED_READ_ONLY
        } else ContentCopy.ITEM_GONE

    /**
     * The line for a vault that cannot take what is put into it (a new item, a move or a copy into it): why it is
     * closed for writing on this device when it is, or the general refusal. A stopped server is said before this.
     */
    private fun notWritableTarget(vaultId: String): String =
        if (source.vaultDeleted(vaultId)) ContentCopy.VAULT_DELETED_READ_ONLY
        else source.closedForWriting(vaultId)?.takeIf { source.vaults().any { v -> v.vaultId == vaultId } }?.let(ContentCopy::closedForWriting)
            ?: ContentCopy.VAULT_NOT_WRITABLE

    override fun recordFillPickedAt(itemId: String, pickedAtMs: Long): Boolean {
        if (pickedAtMs < 0) return false
        val item = fillItem(itemId) ?: return false
        if (FillRules.credential(item) == null && item.doc.card == null) return false
        used(itemId, pickedAtMs)
        return true
    }

    /**
     * The iPhone's AutoFill snapshot of this content (design "Vaults left out of the AutoFill snapshot and the
     * extension"): the logins and cards of the working set only (never of a vault not accepted, frozen, failed or withheld).
     * Null, so the stored one is deleted, when the policy forbids keeping data on this device or there is no login or
     * card to offer. A server stopped on this device (a fork, or a session the server ended) still gets one: its copy is
     * "filled from" (design §4.4), and nothing served is in it since.
     */
    private fun currentFillSnapshot(): ContentFillSnapshot? {
        if (!host.offlineCacheAllowed()) return null
        val items = workingSet().mapNotNull(ContentFillSnapshot::fillable)
        if (items.isEmpty()) return null
        return ContentFillSnapshot(origin = host.origin(), userId = host.userId(), items = items, writtenAtMs = host.wallMs())
    }

    /**
     * Write (or delete) the snapshot from what this content holds now. Nothing before this unlock's copy was read (an
     * empty list then is not "nothing to offer"), once closed, or with no store for it.
     */
    internal fun writeFillSnapshot() {
        if (closed || !opened) return
        fillWriter?.write(currentFillSnapshot())
    }

    override fun credentialIdentities(): List<CredentialIdentity> {
        if (closed || !host.offlineCacheAllowed()) return emptyList()
        return workingSet().flatMap { item ->
            val login = item.doc.login?.takeIf { item.doc.type == "login" && !it.username.isNullOrEmpty() } ?: return@flatMap emptyList()
            // Web addresses only: an app-package address (androidapp://…) names an Android app, never a domain.
            FillRules.addresses(login).mapNotNull { (UriMatch.parseSavedUri(it) as? SavedUri.Web)?.host }.distinct()
                .map { CredentialIdentity(item.itemId, it, login.username!!, !login.totp.isNullOrEmpty()) }
        }
    }

    /** Read the queue (after a sync, or when asked): what may be saved by itself is, through the write path above. */
    private suspend fun readQueue(): ContentSaves.QueueRead {
        val s = saves ?: return ContentSaves.QueueRead.NOT_DONE
        // Stopped here (a fork, or a session the server ended): the captures wait in the queue, untouched, for a sign-in.
        if (closed || source.halted) return ContentSaves.QueueRead.NOT_DONE
        // The list of caught logins is outside a policy that forbids keeping data (decided on 2026-11-18): it is read, and
        // its key published, as without one; nothing but the person's answer, a sign-out or the account's removal empties it.
        val r = s.sync(host.origin(), allowed = true, apply = true)
        if (!closed) {
            when (r) {
                ContentSaves.QueueRead.ENTRIES_REMOVED -> say(ContentSaves.savesUnreadable(s.removedUnread), ContentNoticeKind.RECORDS)
                ContentSaves.QueueRead.UNREADABLE -> say(ContentCopy.SAVES_LIST_UNREADABLE, ContentNoticeKind.RECORDS)
                ContentSaves.QueueRead.READ, ContentSaves.QueueRead.NOT_DONE -> Unit
            }
        }
        publish()
        return r
    }

    override suspend fun readSaveQueue(): ActionResult {
        if (saves == null || closed) return ActionResult.NotDone(null)
        if (source.halted) return ActionResult.Failed(stoppedLine)
        return action {
            when (readQueue()) {
                ContentSaves.QueueRead.UNREADABLE -> ActionResult.Failed(ContentCopy.SAVES_LIST_UNREADABLE)
                ContentSaves.QueueRead.NOT_DONE -> ActionResult.NotDone(null)
                ContentSaves.QueueRead.READ, ContentSaves.QueueRead.ENTRIES_REMOVED -> ActionResult.Ok
            }
        }
    }

    override fun pendingSavePassword(id: String): String? = if (closed) null else saves?.password(id)

    private fun outcome(r: SaveOutcome): ActionResult = when (r) {
        is SaveOutcome.Done -> {
            ContentCopy.kept(r.written)?.let { say(it, ContentNoticeKind.QUEUED) }
            ActionResult.Ok
        }
        SaveOutcome.Gone -> ActionResult.NotDone(null)
        is SaveOutcome.Failed -> ActionResult.Failed(r.message)
    }

    /**
     * One act on the queue or the list of automatic saves. Not while the server is stopped here (a fork, or a session
     * the server ended): the queue and the list are this device's, kept untouched for the next sign-in.
     */
    private suspend fun savesAct(block: suspend (ContentSaves) -> SaveOutcome): ActionResult {
        val s = saves ?: return ActionResult.NotDone(null)
        if (source.halted) return ActionResult.Failed(stoppedLine)
        return action { outcome(block(s)) }
    }

    override suspend fun confirmPendingSave(id: String): ActionResult = savesAct { it.confirm(id) }

    override suspend fun discardPendingSave(id: String): ActionResult = savesAct { it.discard(id) }

    override suspend fun undoAppliedSave(id: String): ActionResult = savesAct { it.undo(id) }

    override suspend fun undoAllAppliedSaves(): ActionResult = savesAct { it.undoAll() }

    override suspend fun dismissAppliedSaves(): ActionResult = savesAct { it.dismiss() }

    /** Why nothing can be written while the item engine is halted: the policy's wipe under way, or a stopped server. */
    private val stoppedLine: String get() = if (host.removingForPolicy()) ContentCopy.COPY_BEING_REMOVED else ContentCopy.SERVER_STOPPED

    /** A failure as the person reads it; a sync state it reveals is kept too. */
    private fun failed(why: ItemFailure, during: ContentCopy.During): ActionResult {
        noteSyncFailure(why)
        // Halted for the policy's wipe: the refusal says why, not that the server is stopped.
        if (why == ItemFailure.Halted && host.removingForPolicy()) return ActionResult.Failed(ContentCopy.COPY_BEING_REMOVED)
        return ActionResult.Failed(ContentCopy.forFailure(why, during))
    }

    // ---- vaults ----

    override fun vaultsForNewItems(): List<VaultChoiceView> {
        if (closed || source.halted) return emptyList()
        return source.vaults().filter { it.writable }.map { VaultChoiceView(it.vaultId, it.name, personal = it.type == "personal") }
    }

    override fun vaultName(vaultId: String): String? = if (closed) null else source.vaults().firstOrNull { it.vaultId == vaultId }?.name

    override fun dismissVaultNotice(id: String) {
        if (closed) return
        source.dismissNotice(id)
        publish()
    }

    // ---- moving and copying ----

    private fun choiceOf(v: VaultView) = VaultChoiceView(v.vaultId, v.name, personal = v.type == "personal")

    override fun moveTargets(itemId: String): List<VaultChoiceView> {
        if (closed || source.halted) return emptyList()
        val item = source.item(itemId) ?: return emptyList()
        return source.vaults().filter { it.writable && it.vaultId != item.vaultId }.map(::choiceOf)
    }

    override fun canMoveOut(itemId: String): Boolean = !closed && source.item(itemId)?.let { writable(it.vaultId) } == true

    override fun cancelMove(itemId: String) {
        if (closed) return
        moves.cancelled(itemId)
    }

    override suspend fun moveOrCopyItem(itemId: String, targetVaultId: String, move: Boolean): ActionResult =
        moveOrCopyItemWithId(itemId, targetVaultId, move).result

    override suspend fun moveOrCopyItemWithId(itemId: String, targetVaultId: String, move: Boolean): MoveMade {
        var planned: String? = null
        val r = moveOrCopy(itemId, targetVaultId, move) { planned = it }
        // The copy is named only when it is in the target as this device sees it now, whatever the answer says.
        val made = planned?.takeIf { !closed && source.item(it)?.vaultId == targetVaultId }
        return MoveMade(r, made)
    }

    private suspend fun moveOrCopy(itemId: String, targetVaultId: String, move: Boolean, planned: (String) -> Unit): ActionResult = action {
        if (source.halted) return@action ActionResult.Failed(stoppedLine)
        if (source.item(itemId) == null) return@action ActionResult.Failed(ContentCopy.ITEM_GONE)
        // What was kept must be read first: a plan kept but not read would be planned afresh, and copied twice.
        moves.unreadable()?.let { return@action notRead(it) }
        // A kept try is replayed only while its copy is in the target, as a sync just before shows it (round-7 review
        // M3): a replayed copy leg is answered from the server's journal, so a copy deleted since would let the delete
        // leg remove the only original. A sync that fails replays nothing unchecked.
        val keptTry = moves.kept(itemId, targetVaultId, move)
        if (keptTry != null) {
            val s = source.sync()
            if (s is ItemResult.Failed && s.why !is ItemFailure.Denied) {
                noteSyncFailure(s.why)
                return@action failed(s.why, ContentCopy.During.OTHER)
            }
        }
        val current = source.item(itemId) ?: return@action ActionResult.Failed(ContentCopy.ITEM_GONE)
        if (move && !writable(current.vaultId)) return@action ActionResult.Failed(readOnlyLine(current.vaultId))
        if (moveTargets(itemId).none { it.vaultId == targetVaultId }) return@action ActionResult.Failed(notWritableTarget(targetVaultId))
        // Null where this device cannot read a vault's name, blank for an item with none: each line says plain words
        // there ("the other vault", "its vault", "This item"), never inside quotation marks as if it were a name.
        val target = vaultName(targetVaultId)
        val from = vaultName(current.vaultId)
        val name = current.doc.name
        val copyInTarget = keptTry != null && source.item(keptTry.gesture.newItemId)?.vaultId == targetVaultId
        // Into a vault the account owns, the copy counts against its own space (spec 03 §14.4). The last use and limits
        // this device holds are read first, so a run of moves ("Move everything") costs no sync each; only a "short"
        // there is checked again on a fresh sync, and only a fresh "short" stops the move before anything is sent.
        if (!copyInTarget && ownedHere(targetVaultId)) {
            val size = source.copySize(listOf(current.doc), fileMax(), null)
            val last = SpaceCheck.of(QuotaCheck.room(source.quota(), size), SpaceFor.MOVE_OR_COPY, targetVaultId)
            when (last.verdict) {
                SpaceVerdict.NOT_ENOUGH -> freshGate(size, SpaceFor.MOVE_OR_COPY, targetVaultId)?.let { return@action it }
                SpaceVerdict.NOT_ENOUGH_ON_DECLARED_SIZES -> said(last)
                else -> Unit
            }
        }
        var planFailure: ItemFailure? = null
        val prepared = moves.prepare(itemId, current.rev, targetVaultId, move, copyInTarget) {
            when (val p = source.planMove(itemId, targetVaultId, move)) {
                is ItemResult.Ok -> p.value
                is ItemResult.Failed -> null.also { planFailure = p.why }
            }
        }
        planFailure?.let { return@action failed(it, ContentCopy.During.OTHER) }
        val plan = when (prepared) {
            ContentMoves.Prepared.NotPlanned -> return@action ActionResult.Failed(ContentCopy.MOVE_RETRY)
            ContentMoves.Prepared.Locked, ContentMoves.Prepared.Unreadable -> return@action notRead(prepared)
            is ContentMoves.Prepared.AlreadyCopied -> {
                keptTry?.let { planned(it.gesture.newItemId) }
                return@action ActionResult.Failed(ContentCopy.alreadyCopied(name, target, prepared.changedSince))
            }
            is ContentMoves.Prepared.Run -> prepared.plan
        }
        planned(plan.targetItemId)
        when (val r = cutting({ unsaved.cut(if (move) LockCutKind.MOVE else LockCutKind.ITEM_COPY, current.doc.name, target ?: "") }) { source.runMove(plan, null, true) }) {
            is ItemResult.Ok -> {
                moves.finished(itemId, targetVaultId, move)
                say(if (move) ContentCopy.moved(target) else ContentCopy.copied(target), ContentNoticeKind.DONE)
                ActionResult.Ok
            }
            is ItemResult.Failed -> {
                val why = r.why
                val refusal = (why as? ItemFailure.NotAllowed)?.reason
                when {
                    refusal == ItemRefusal.SOURCE_DELETE_DENIED -> {
                        // The copy was made and seen: a later try must find it still there (M3).
                        moves.copyMade(itemId, targetVaultId, move)
                        ActionResult.Failed(ContentCopy.inBothVaults(name, target, from))
                    }
                    refusal == ItemRefusal.ITEM_CHANGED -> {
                        // Before the copy (a file went) or after it (the original changed): a later try checks the target.
                        moves.copyMade(itemId, targetVaultId, move)
                        failed(why, ContentCopy.During.OTHER)
                    }
                    refusal == ItemRefusal.COPY_DENIED || refusal == ItemRefusal.ITEM_CHANGED_VAULTS || refusal == ItemRefusal.ITEM_GONE ||
                        (why is ItemFailure.Refused && why.status == 403) -> {
                        moves.finished(itemId, targetVaultId, move)
                        failed(why, ContentCopy.During.OTHER)
                    }
                    // No answer, or a copy not confirmed: the plan is kept, so Try again replays the same ids.
                    refusal == ItemRefusal.COPY_UNCONFIRMED -> ActionResult.Failed(ContentCopy.MOVE_RETRY)
                    why is ItemFailure.Unreachable || why is ItemFailure.Refused -> {
                        noteSyncFailure(why)
                        ActionResult.Failed(ContentCopy.MOVE_RETRY)
                    }
                    else -> failed(why, ContentCopy.During.OTHER)
                }
            }
        }
    }

    /** What was kept about moves cannot be read now: locked (the content is closing, nothing to say) or unreadable. */
    private fun notRead(why: ContentMoves.Prepared): ActionResult =
        if (why == ContentMoves.Prepared.Locked) ActionResult.NotDone(null) else ActionResult.Failed(ContentCopy.MOVES_UNREADABLE)

    override suspend fun saveVaultItemsToPersonal(vaultId: String): ActionResult = action {
        if (copying != null) return@action ActionResult.Failed(ContentCopy.COPY_RUNNING)
        if (source.halted) return@action ActionResult.Failed(stoppedLine)
        val personal = source.personalVaultId ?: return@action ActionResult.Failed(ContentCopy.NO_PERSONAL_VAULT)
        val held = source.heldVaults().firstOrNull { it.vaultId == vaultId }
        // The personal vault is the account's own: the copy is checked on a fresh sync before anything is sent.
        val docs = (if (held != null) source.heldItems(vaultId) else source.items().filter { it.vaultId == vaultId }).map { it.doc }
        freshGate(source.copySize(docs, fileMax(), null), SpaceFor.INTO_PERSONAL, personal)?.let { return@action it }
        if (closed) return@action ActionResult.NotDone(null)
        copying = CopyProgressView(vaultId, 0, held?.itemCount ?: source.items().count { it.vaultId == vaultId })
        publish()
        val progress: (Int, Int) -> Unit = { done, total ->
            copying = CopyProgressView(vaultId, done, total)
            publish()
        }
        // A lock that cuts the copy short is said at the next unlock, with how many were copied at least, of how many.
        val from = held?.name ?: vaultName(vaultId) ?: ""
        val into = vaultName(personal) ?: ""
        val cut = { copying?.let { unsaved.cut(LockCutKind.PERSONAL_COPY, from, into, it.done, it.total) } ?: Unit }
        try {
            if (held != null) {
                when (val r = cutting(cut) { source.rescueHeldToPersonal(vaultId, progress) }) {
                    is ItemResult.Ok -> {
                        say(ContentCopy.copiedOutOfHeld(r.value.copied, r.value.filesLeftOut), ContentNoticeKind.DONE)
                        ActionResult.Ok
                    }
                    is ItemResult.Failed -> failed(r.why, ContentCopy.During.OTHER)
                }
            } else {
                when (val r = cutting(cut) { source.rescueToPersonal(vaultId, progress) }) {
                    is ItemResult.Ok -> {
                        say(ContentCopy.copiedToPersonal(r.value), ContentNoticeKind.DONE)
                        ActionResult.Ok
                    }
                    is ItemResult.Failed -> failed(r.why, ContentCopy.During.OTHER)
                }
            }
        } finally {
            copying = null
        }
    }

    override suspend fun bringHeldItemsInto(fromVaultId: String, targetVaultId: String, picks: List<HeldPick>): HeldBrought {
        val made = ArrayList<HeldCopied>()
        val deleted = ArrayList<io.silencelen.andvari.core.client.items.HeldDeleted>()
        val r = action {
            if (copying != null) return@action ActionResult.Failed(ContentCopy.COPY_RUNNING)
            if (source.halted) return@action ActionResult.Failed(stoppedLine)
            if (!writable(targetVaultId)) {
                val known = source.vaults().any { it.vaultId == targetVaultId }
                return@action ActionResult.Failed(if (known || source.vaultDeleted(targetVaultId)) readOnlyLine(targetVaultId) else ContentCopy.VAULT_NOT_WRITABLE)
            }
            // A fresh sync first: a copy an earlier run made, whose answer a restart lost, is found and not made again,
            // and into a vault the account owns, what is left to copy is checked on the use and limits it served.
            val s = source.sync()
            if (s is ItemResult.Failed && s.why !is ItemFailure.Denied) {
                noteSyncFailure(s.why)
                return@action failed(s.why, ContentCopy.During.OTHER)
            }
            if (closed) return@action ActionResult.NotDone(null)
            val docs = source.heldDocsToBring(fromVaultId, targetVaultId, picks)
            if (docs.isNotEmpty() && ownedHere(targetVaultId)) {
                val check = SpaceCheck.of(QuotaCheck.room(source.quota(), source.copySize(docs, fileMax(), null)), SpaceFor.MOVE_OR_COPY, targetVaultId)
                said(check)
                if (check.verdict == SpaceVerdict.NOT_ENOUGH) return@action ActionResult.Failed(ContentCopy.outOfSpace(check))
            }
            copying = CopyProgressView(fromVaultId, 0, picks.size)
            publish()
            val progress: (Int, Int) -> Unit = { done, total ->
                copying = CopyProgressView(fromVaultId, done, total)
                publish()
            }
            val from = source.heldVaults().firstOrNull { it.vaultId == fromVaultId }?.name ?: vaultName(fromVaultId) ?: ""
            // Blank where the name cannot be read: the lines say "a vault" there, unquoted.
            val into = vaultName(targetVaultId) ?: ""
            val cut = { copying?.let { unsaved.cut(LockCutKind.VAULT_COPY, from, into, it.done, it.total) } ?: Unit }
            try {
                when (val b = cutting(cut) { source.bringHeldInto(fromVaultId, targetVaultId, picks, { made += it }, progress, { deleted += it }) }) {
                    is ItemResult.Ok -> {
                        val leftOut = b.value.sumOf { it.filesLeftOut }
                        // The app interface says what was copied; only files left out are this content's to say, and
                        // the count is of the copies made: an item the person deleted is not one, nor one whose copy was
                        // deleted in the target since (it was not copied again).
                        if (leftOut > 0) say(ContentCopy.broughtInto(into, b.value.count { !it.deletedThere }, leftOut), ContentNoticeKind.DONE)
                        ActionResult.Ok
                    }
                    is ItemResult.Failed -> failed(b.why, ContentCopy.During.OTHER)
                }
            } finally {
                copying = null
            }
        }
        return HeldBrought(r, made.toList(), deleted.toList(), made.count { it.deletedThere })
    }

    override suspend fun spaceForMoveEverything(vaultId: String, newVaultName: String?, copiedItemIds: List<String>): SpaceCheck? {
        if (closed) return null
        val copied = copiedItemIds.toHashSet()
        val docs = source.items().filter { it.vaultId == vaultId && it.itemId !in copied }.map { it.doc }
        val r = source.roomFor(source.copySize(docs, fileMax(), newVaultName))
        publish()
        if (closed) return null
        return (r as? ItemResult.Ok)?.let { SpaceCheck.of(it.value, SpaceFor.MOVE_EVERYTHING, null) }
    }

    override fun heldItems(vaultId: String): List<ItemSummary> =
        if (closed) {
            emptyList()
        } else {
            // A held copy is read only, in a vault the account no longer has: its name is the held row's, and no Edit.
            val name = source.heldVaults().firstOrNull { it.vaultId == vaultId }?.name?.let { ItemText.label(it) }?.ifEmpty { null }
            source.heldItems(vaultId).sortedBy { it.doc.name.lowercase() }.map { summaryOf(it, false, null, source.halted).copy(vaultName = name, sharedVault = true) }
        }

    override fun removeFromDevice(vaultId: String): ActionResult {
        if (closed) return ActionResult.NotDone(null)
        if (source.halted) return ActionResult.Failed(stoppedLine)
        val r = source.removeFromDevice(vaultId)
        publish()
        return when (r) {
            is ItemResult.Ok -> ActionResult.Ok
            is ItemResult.Failed ->
                if ((r.why as? ItemFailure.NotAllowed)?.reason == ItemRefusal.VAULT_READ_ONLY) ActionResult.Failed(ContentCopy.STILL_YOURS)
                else ActionResult.Failed(ContentCopy.forFailure(r.why, ContentCopy.During.OTHER))
        }
    }

    override suspend fun renameSharedVault(vaultId: String, name: String): ActionResult = action {
        val trimmed = name.trim()
        if (trimmed.isEmpty()) return@action ActionResult.Failed(ContentCopy.VAULT_NAME_REQUIRED)
        if (source.halted) return@action ActionResult.Failed(stoppedLine)
        val v = source.vaults().firstOrNull { it.vaultId == vaultId && it.type == "shared" } ?: return@action ActionResult.Failed(ContentCopy.VAULT_NOT_OPEN)
        if (v.role != VaultAccess.ROLE_OWNER) return@action ActionResult.Failed(ContentCopy.NOT_VAULT_OWNER)
        if (!v.writable) return@action ActionResult.Failed(readOnlyLine(vaultId))
        when (val r = source.renameVault(vaultId, trimmed)) {
            is ItemResult.Ok -> ActionResult.Ok
            is ItemResult.Failed -> failed(r.why, ContentCopy.During.OTHER)
        }
    }

    // ---- vault health ----

    /** The role this device may act with in [vaultId]: a vault it cannot write counts as a reader's, so core's plans refuse it. */
    private fun roleForWrite(vaultId: String): String? {
        val v = source.vaults().firstOrNull { it.vaultId == vaultId } ?: return null
        return if (!source.halted && v.writable) v.role else VaultAccess.ROLE_READER
    }

    /** A health write: an ordinary save of the item in the vault it is in now (INV-EDIT). Null, or the failure's sentence. */
    private suspend fun healthSave(itemId: String, doc: ItemDoc): String? {
        if (source.halted) return stoppedLine
        val item = source.item(itemId) ?: return ContentCopy.ITEM_GONE
        return when (val r = notingUnkept(item.doc.name, itemId) { source.save(itemId, doc, item.vaultId, emptyList(), null, null, null) }) {
            is ItemResult.Ok -> {
                ContentCopy.kept(r.value.outcome)?.let { say(it, ContentNoticeKind.QUEUED) }
                null
            }
            is ItemResult.Failed -> {
                noteSyncFailure(r.why)
                ContentCopy.forFailure(r.why, ContentCopy.During.SAVE)
            }
        }
    }

    private suspend fun healthRemove(itemId: String): String? {
        if (source.halted) return stoppedLine
        return when (val r = source.remove(itemId)) {
            is ItemResult.Ok -> {
                keptItemDeleted(itemId)
                null
            }
            is ItemResult.Failed -> {
                noteSyncFailure(r.why)
                ContentCopy.forFailure(r.why, ContentCopy.During.SAVE)
            }
        }
    }

    override fun itemHealth(): Map<String, ItemHealthLine> =
        if (closed) emptyMap() else healthPart.lines(source.items(), source.pendingSyncItemIds())

    override fun loginAges(): Map<String, LoginAgeLine> = if (closed) emptyMap() else healthPart.ages(source.items())

    override fun cardExpiry(itemId: String): CardExpiryView? {
        if (closed) return null
        val card = source.item(itemId)?.doc?.takeIf { it.type == "card" }?.card ?: return null
        val label = CardDisplay.expiryLabel(card) ?: return null
        val today = kotlinx.datetime.Instant.fromEpochMilliseconds(wallMs()).toLocalDateTime(kotlinx.datetime.TimeZone.currentSystemDefault())
        return CardExpiryView(
            label,
            CardDisplay.isExpired(card.expMonth, card.expYear, today.year, today.monthNumber),
            CardNormalize.composeShortExpiry(card.expMonth ?: "", card.expYear ?: ""),
        )
    }

    override fun cardBrandOf(number: String): String? = CardDisplay.brandLabel(CardNormalize.brand(number))

    override fun openHealth() {
        if (closed) return
        healthPart.open()
        publish()
    }

    override fun closeHealth() {
        healthPart.health = null
        publish()
    }

    override fun refreshHealth() = publish()

    override fun setHealthShowSnoozed(show: Boolean) {
        healthPart.health?.showSnoozed = show
        publish()
    }

    override fun dismissHealthMessage() {
        healthPart.health?.message = null
        publish()
    }

    override suspend fun checkBreaches(): ActionResult = action(readOnly = true) {
        if (source.halted) return@action ActionResult.Failed(stoppedLine)
        healthPart.checkBreaches(::publish) { !closed }
    }

    override suspend fun mergeDuplicates(signature: String): ActionResult = action { healthPart.mergeDuplicates(signature) }

    override suspend fun keepDuplicate(signature: String, keepId: String): ActionResult = action { healthPart.keepDuplicate(signature, keepId) }

    override suspend fun markNotDuplicates(signature: String): ActionResult = action { healthPart.acknowledgeCluster(signature, restoring = false) }

    override suspend fun restoreDuplicates(signature: String): ActionResult = action { healthPart.acknowledgeCluster(signature, restoring = true) }

    override fun startCheckRun(neverCheckedOnly: Boolean) {
        val rows = healthPart.view()?.staleness.orEmpty().filter { !neverCheckedOnly || it.neverChecked }
        healthPart.beginRun(rows.map { it.itemId })
        publish()
    }

    override fun checkLogin(itemId: String) {
        healthPart.beginRun(listOf(itemId))
        publish()
    }

    override fun skipCheck() {
        healthPart.health?.let(healthPart::advanceRun)
        publish()
    }

    override fun stopCheckRun() {
        healthPart.health?.let {
            it.queue = emptyList()
            it.index = 0
        }
        publish()
    }

    override suspend fun recordCheck(itemId: String, result: String): ActionResult = action { healthPart.recordCheck(itemId, result) }

    override suspend fun unsnoozeLogin(itemId: String): ActionResult = action { healthPart.unsnoozeLogin(itemId) }

    override suspend fun trashGoneLogin(): ActionResult = action { healthPart.trashGoneLogin() }

    override fun keepGoneLogin() {
        healthPart.health?.offerDelete = null
        publish()
    }

    override fun answerBadOffer(opening: Boolean) {
        val h = healthPart.health ?: return
        h.offerBad = null
        if (opening) {
            h.offerDelete = null
            h.queue = emptyList()
            h.index = 0
        }
        publish()
    }

    // ---- import and export ----

    override suspend fun importCsv(bytes: ByteArray): ActionResult = try {
        action { ports.importCsv(bytes) }
    } finally {
        bytes.fill(0)
    }

    override suspend fun setImportVault(vaultId: String): ActionResult = action { ports.setImportVault(vaultId, ::publish) }

    override suspend fun confirmImport(): ActionResult = action { ports.confirmImport(::publish) }

    override fun closeImport() {
        ports.csv = null
        if (space?.forWhat == SpaceFor.CSV_IMPORT) space = null
        publish()
    }

    override suspend fun openExport(kind: ExportKind): ActionResult = action(readOnly = true) {
        // An export holds what the server has (spec 07); offline or stopped, the copy as of the last sync, said so.
        val r = runSync()
        val offline = r !is ActionResult.Ok && (sync == VaultSyncState.OFFLINE || source.halted)
        if (r is ActionResult.Failed && !offline) return@action r // a refused sync is said, never exported over
        ports.openExport(kind, offline)
        ActionResult.Ok
    }

    override fun setExportVault(vaultId: String, included: Boolean) {
        ports.setExportVault(vaultId, included)
        publish()
    }

    override fun setExportAttachments(include: Boolean) {
        ports.setExportAttachments(include)
        publish()
    }

    override fun closeExport() {
        ports.exporting = null
        publish()
    }

    override fun csvFile(acknowledged: Boolean): ExportFile? {
        if (closed) return null
        val f = ports.csvFile(acknowledged)
        publish()
        return f
    }

    override suspend fun backupFile(passphrase: String, confirm: String): ExportFile? {
        if (closed) return null
        try {
            return ports.backupFile(passphrase, confirm, ::publish) { !closed }
        } finally {
            publish()
        }
    }

    override suspend fun backupFileChars(passphrase: CharArray, confirm: CharArray): ExportFile? = try {
        backupFile(passphrase.concatToString(), confirm.concatToString())
    } finally {
        passphrase.fill(0.toChar())
        confirm.fill(0.toChar())
    }

    override fun exportSaved(fileName: String, folder: String) {
        ports.exportSaved(fileName, folder)
        publish()
    }

    override fun exportNotSaved(written: Boolean) {
        ports.exportNotSaved(written)
        publish()
    }

    // ---- sync ----

    /** The first sync of this unlock shows this device's copy before it talks to the server. */
    private suspend fun openOnce() {
        if (opened) return
        opened = true
        source.hydrate()
        // What was kept is read now, so a record this version cannot read is said at once, not at the next move. Not
        // while the server is stopped here (a fork, or a session the server ended): the copy is read, nothing written.
        if (!source.halted) moves.check()
        // The unlock's snapshot, from this device's copy, before the server is asked anything.
        writeFillSnapshot()
        publish()
    }

    override suspend fun refresh(): ActionResult = action {
        val before = notice
        val r = runSync()
        // A line the sync itself set (a kept save finished) is not covered by "Synced.".
        if (r is ActionResult.Ok && notice === before) say(ContentCopy.SYNCED, ContentNoticeKind.DONE)
        r
    }

    override fun movesWaiting(): Int? = if (closed) null else moves.waiting()

    override fun keptSavesWaiting(): Int? {
        if (closed) return null
        val all = (kept.load() as? KeptRead.Read)?.value ?: return null
        // A save whose change waits in the durable queue is counted there, once.
        val pending = source.pendingSyncItemIds()
        return all.count { it.queuedAt == null || it.newItemId !in pending }
    }

    /**
     * One kept save as one change of a policy's one attempt before the copy is removed: its files, set aside encrypted,
     * which go up first, then its item's put, sealed now. [put] is null when it cannot be sent as it was made (a file of
     * it is not on this device or could not be read, or it could not be sealed: the account locked): counted as not sent.
     */
    internal class KeptChange(val itemId: String, val vaultId: String, val files: List<Pair<String, ByteArray>>, val put: io.silencelen.andvari.core.model.wire.Mutation?)

    /**
     * The saves counted by [keptSavesWaiting], each as a [KeptChange], sealed while the account is open: what the attempt
     * then sends needs no key. A save the server already holds with its files is not one. Null when they cannot be read.
     * The put is built as [finishKept] builds it (a save older than what happened since adds only its files to the item
     * as it is now) under an id derived from the save, so a second attempt sends the same change, which the server takes
     * once.
     */
    internal fun keptChangesForAttempt(): List<KeptChange>? {
        if (closed) return null
        val all = (kept.load() as? KeptRead.Read)?.value ?: return null
        val pending = source.pendingSyncItemIds()
        return all.filter { (it.queuedAt == null || it.newItemId !in pending) && !landed(it) }.map { keptChange(it, pending) }
    }

    private fun keptChange(p: KeptSave, pending: Set<String>): KeptChange {
        val refs = p.doc.attachments.associateBy { it.id }
        val files = ArrayList<Pair<String, ByteArray>>()
        for (id in p.newFiles) {
            val sealed = if (refs[id] == null) null else (kept.blob(id) as? KeptRead.Read)?.value
            sealed ?: return KeptChange(p.newItemId, p.vaultId, emptyList(), null)
            files += id to sealed
        }
        val current = p.itemId?.let { source.item(it) }
        val older = current != null && (current.rev != p.baseRev || p.itemId in pending)
        val doc = if (older) current!!.doc.copy(attachments = current.doc.attachments.filter { it.id !in p.newFiles } + p.doc.attachments.filter { it.id in p.newFiles }) else p.doc
        val base = if (older) current!!.rev else p.baseRev
        val mutationId = Bytes.uuidV4FromBytes(crypto.sha256("kept-save|${p.id}|$base".encodeToByteArray()))
        val put = try {
            (source.sealedPut(mutationId, p.newItemId, doc, p.vaultId, base, isNew = p.itemId == null) as? ItemResult.Ok)?.value
        } catch (e: KeysGoneException) {
            null // locked: nothing is sealed, and the save counts as not sent
        }
        return KeptChange(p.newItemId, p.vaultId, files, put)
    }

    override suspend fun syncQuietly(): ActionResult {
        if (closed) return ActionResult.NotDone(null)
        writing.update { it + 1 }
        return try {
            val r = runSync()
            // A refusal of this device's own writes is never silent, even when nobody asked for the sync.
            if (r is ActionResult.Failed && lastSyncDenied) error = r.message
            if (closed) ActionResult.NotDone(null) else r
        } catch (c: CancellationException) {
            throw c
        } catch (t: Throwable) {
            if (closed) ActionResult.NotDone(null) else ActionResult.Failed(ContentCopy.SYNC_FAILED)
        } finally {
            publish()
            writing.update { it - 1 }
        }
    }

    /** The last sync completed and the server denied some of this device's own writes ([ItemFailure.Denied]). */
    private var lastSyncDenied = false

    private suspend fun runSync(): ActionResult {
        lastSyncDenied = false
        openOnce()
        if (source.halted) return ActionResult.Failed(stoppedLine)
        syncs++
        publish()
        try {
            return when (val r = source.sync()) {
                is ItemResult.Ok -> {
                    sync = VaultSyncState.SYNCED
                    ports.lastSyncedAt = wallMs()
                    saves?.pulled()
                    // Pull first, then decide (round-10 review 5): a kept save is judged against the server's copy.
                    giveUpRefusedKeptSaves()
                    resumeKeptSaves()
                    settleQueuedKeptSaves()
                    readQueue()
                    writeFillSnapshot()
                    // "Last used" for Health: once per unlock, and after every sync while its screen is open.
                    if (healthPart.usageWanted && !closed) healthPart.readUsage()
                    ActionResult.Ok
                }
                is ItemResult.Failed -> {
                    lastSyncDenied = r.why is ItemFailure.Denied
                    // The cycle completed, with some of this device's writes refused: the snapshot follows what is held,
                    // and a save kept for a change the server refused for good is let go and said.
                    if (lastSyncDenied) {
                        giveUpRefusedKeptSaves()
                        writeFillSnapshot()
                    }
                    failed(r.why, ContentCopy.During.SYNC)
                }
            }
        } finally {
            syncs--
        }
    }

    /** What a failure says about the server, as [ContentState.sync] shows it. */
    private fun noteSyncFailure(why: ItemFailure) {
        sync = when (why) {
            is ItemFailure.Unreachable -> VaultSyncState.OFFLINE
            is ItemFailure.Rollback -> VaultSyncState.ROLLBACK
            // Halted for the policy's wipe is not a stopped server: the state stays as it was.
            ItemFailure.Halted -> if (host.removingForPolicy()) return else VaultSyncState.STOPPED
            is ItemFailure.Refused -> VaultSyncState.REFUSED
            // The cycle completed; only some of this device's own writes were refused.
            is ItemFailure.Denied -> VaultSyncState.SYNCED
            is ItemFailure.NotAllowed, is ItemFailure.Corrupt -> return
        }
    }

    override fun dismissError() {
        error = null
        space = null
        publish()
    }

    override fun dismissNotice() {
        notice = null
        noticeKind = null
        lockCut = emptyList()
        publish()
    }

    // ---- the list's rows ----

    /**
     * One row of a list. [vault] is the item's vault as this build read it (null: the device holds no such vault, as for
     * a held copy of one that went), so nothing here reads a vault, the server or a key per row.
     */
    private fun summaryOf(item: VaultItem, pending: Boolean, vault: VaultView?, stopped: Boolean): ItemSummary {
        val doc = item.doc
        val first = doc.login?.uris?.firstOrNull()
        // The brand is worked out from the number, never read from the stored field (another writer may have left it stale).
        val digits = doc.card?.takeIf { doc.type == "card" }?.number?.let(CardNormalize::digitsOnly)?.ifEmpty { null }
        // A list row shows what the item's writer chose: each part is one safe line ([ItemText.label]).
        return ItemSummary(
            itemId = item.itemId, name = ItemText.label(doc.name), type = doc.type,
            username = doc.login?.username?.let { ItemText.label(it) }?.ifEmpty { null },
            host = first?.let(::hostOf)?.let { ItemText.label(it) }?.ifEmpty { null },
            favorite = doc.favorite, hasTotp = !doc.login?.totp.isNullOrEmpty(), pendingSync = pending,
            vaultId = item.vaultId,
            vaultName = vault?.name?.let { ItemText.label(it) }?.ifEmpty { null },
            sharedVault = vault != null && vault.type != "personal",
            cardBrand = digits?.let { CardDisplay.brandLabel(CardNormalize.brand(it)) },
            cardLastFour = digits?.takeLast(4),
            updatedAt = item.updatedAt,
            // The rule of [itemDetail]'s `editable`, from the same vault row.
            editable = !stopped && doc.type in EDITABLE_TYPES && vault?.writable == true,
        )
    }

    internal companion object {
        val EDITABLE_TYPES = setOf("login", "card", "note")
        const val CARD_NUMBER_MAX_DIGITS = 19
        const val NEW_ITEM = "new"

        /** Releases of one item closer together than this are one use ([used]). */
        const val USE_WINDOW_MS = 60_000L

        /**
         * A kept file this unlock put on the server less than this long ago is not sent again before a drain: the server
         * keeps an upload no item names for a day, so half a day leaves the margin.
         */
        const val KEPT_FILE_RESEND_AFTER_MS = 12L * 60 * 60 * 1000

        /** A fresh canonical id (an item, an attachment). */
        fun freshId(crypto: CryptoProvider): String = Bytes.uuidV4FromBytes(crypto.randomBytes(16))

        /** The name, the notes, the username, every web address and a card's brand and last four (parity with web, desktop and Android). */
        fun matches(item: VaultItem, q: String): Boolean {
            if (q.isEmpty()) return true
            val d = item.doc
            return d.name.lowercase().contains(q) ||
                (d.notes ?: "").lowercase().contains(q) ||
                (d.login?.username ?: "").lowercase().contains(q) ||
                (d.login?.uris ?: emptyList()).any { it.lowercase().contains(q) } ||
                (d.type == "card" && CardDisplay.subtitle(d).lowercase().contains(q))
        }

        /** The host of a stored web address, for display: "https://user@login.example.com:8443/x" is login.example.com. */
        fun hostOf(uri: String): String? {
            val afterScheme = uri.substringAfter("://", uri)
            val authority = afterScheme.takeWhile { it != '/' && it != '?' && it != '#' }.substringAfterLast('@')
            val host = if (authority.startsWith("[")) authority.substringBefore(']').plus("]") else authority.substringBefore(':')
            return host.lowercase().ifEmpty { null }
        }
    }
}
