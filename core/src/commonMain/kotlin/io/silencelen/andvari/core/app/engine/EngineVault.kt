package io.silencelen.andvari.core.app.engine

import io.silencelen.andvari.core.app.AttachmentLimitsView
import io.silencelen.andvari.core.app.AttachmentRules
import io.silencelen.andvari.core.app.Subscription
import io.silencelen.andvari.core.app.content.ContentHost
import io.silencelen.andvari.core.app.content.EngineVaultContent
import io.silencelen.andvari.core.app.content.VaultContent
import io.silencelen.andvari.core.client.InMemoryVaultCache
import io.silencelen.andvari.core.client.VaultCache
import io.silencelen.andvari.core.client.devicelink.BundleCheckpoints
import io.silencelen.andvari.core.client.items.BellSocket
import io.silencelen.andvari.core.client.items.EventBell
import io.silencelen.andvari.core.client.items.ItemCacheNames
import io.silencelen.andvari.core.client.items.ItemEngine
import io.silencelen.andvari.core.client.items.ItemStore
import io.silencelen.andvari.core.client.items.PinnedOriginGate
import io.silencelen.andvari.core.client.items.SessionVaultKeys
import io.silencelen.andvari.core.client.items.VaultRows
import io.silencelen.andvari.core.client.items.WireItemTransport
import io.silencelen.andvari.core.client.link.AccountContactBook
import io.silencelen.andvari.core.client.link.ContactCurrency
import io.silencelen.andvari.core.client.link.LinkAccount
import io.silencelen.andvari.core.client.log.StoredVaultLogs
import io.silencelen.andvari.core.client.log.VaultLogHost
import io.silencelen.andvari.core.client.onboard.EstablishedSession
import io.silencelen.andvari.core.client.onboard.SessionHow
import io.silencelen.andvari.core.client.sqliteVaultCache
import io.silencelen.andvari.core.client.state.StoredAccountState
import io.silencelen.andvari.core.crypto.KdfParams
import io.silencelen.andvari.core.model.wire.SyncGrant
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.drop
import kotlinx.coroutines.launch

/**
 * Where the offline caches of the item engine live (spec 02 §8): one file per origin and account, named by
 * [ItemCacheNames.fileName]. The app gives one to [AppEngine.cacheFiles]; without one every cache is in memory and
 * nothing of the vault is kept at rest between unlocks.
 */
interface VaultCacheFiles {
    /** Open the cache file [fileName] (made when it is not there) for the account [userId]. */
    fun open(fileName: String, userId: String): VaultCache

    /** Delete the cache file [fileName] and whatever the database keeps beside it. True when nothing of it is left. */
    fun delete(fileName: String): Boolean

    /**
     * Rename the one file [from] to [to] (a followed move carries the cache, design §4.4), never over a file that is
     * there: true once [from] is at [to], or when there is no [from]. False keeps both names as they are; the default
     * (a platform that cannot rename) carries nothing, and the copy stays under its old name until the person's own
     * end deletes it.
     */
    fun rename(from: String, to: String): Boolean = false
}

/**
 * [VaultCacheFiles] as SQLite files in [dir]. [remove] deletes one file by its path and answers true when it is gone
 * (or was never there); [move], when given, renames one path to another without overwriting, as [VaultCacheFiles.rename]
 * says. The app gives its platform's file calls.
 */
class SqliteVaultCacheFiles(
    private val dir: String,
    private val remove: (path: String) -> Boolean,
) : VaultCacheFiles {
    private var move: ((from: String, to: String) -> Boolean)? = null

    /** With [move], the platform's rename without overwrite: a followed move carries the cache files. */
    constructor(dir: String, move: (from: String, to: String) -> Boolean, remove: (path: String) -> Boolean) : this(dir, remove) {
        this.move = move
    }

    private fun path(fileName: String) = dir.trimEnd('/') + "/" + fileName

    override fun rename(from: String, to: String): Boolean = move?.invoke(path(from), path(to)) ?: false

    override fun open(fileName: String, userId: String): VaultCache = sqliteVaultCache(path(fileName), userId)

    override fun delete(fileName: String): Boolean {
        val p = path(fileName)
        // The journal files go too: they can hold rows of the database.
        return listOf(p, "$p-wal", "$p-shm", "$p-journal").map(remove).all { it }
    }
}

/**
 * What one unlock of the engine-backed API opened over the account (design §3, §5; the command-line tool's
 * `AccountSession`): the account state, the contacts, the vault-log engine, the item engine on its cache and the
 * vault's content. Made when the vault opens and dropped when it locks: nothing of it outlives the keys it was made
 * with. The cache file stays across a lock and goes when the session ends ([EngineAppApi.dropVault]).
 */
internal class EngineVault private constructor(
    private val app: EngineAppApi,
    val origin: String,
    val userId: String,
    /**
     * The account as the link engine sees it ([io.silencelen.andvari.core.client.link.WireLinkFlows] takes it, read at
     * each step). Replaced only by [named].
     */
    link: LinkAccount,
    /** The account's contacts on this device (the vault-log host reads the same book). */
    val contacts: AccountContactBook,
    /** The account's state document (contacts, records), one copy per unlock. */
    val store: StoredAccountState,
    val logs: StoredVaultLogs,
    val items: ItemEngine,
    val content: EngineVaultContent,
    /** The vault and grant rows of the last pull, as the item engine's key source keeps them (the shared vaults' list). */
    val rows: VaultRows,
    /** The vault the account genesis names: the personal vault, which has no log and is no shared vault. */
    val personalVaultId: String,
    /** The policy as read at the composition allowed an offline copy: the cache and the kept records are files. */
    val keptAtRest: Boolean,
    /** The bell socket the transport's dialer gave for [origin] at this opening, or null: no bell. */
    private val bellSocket: BellSocket?,
    /** Composed over a copy the server signed out: the item engine is halted before the content's first use. */
    val signedOutByServer: Boolean,
    /** The item engine's cache of this opening (a file only while [keptAtRest]). */
    private val cache: VaultCache,
    /**
     * Composed while the session's server answers "update required": the copy is read-only (the item engine is halted
     * before first use) until a composition after that state cleared.
     */
    val haltedForUpdate: Boolean,
    /** The highest rev a pull or a push of this opening was answered at: what the bell's rings are measured against. */
    private val answered: AnsweredRev,
    /** The usage ledger's store for this opening (spec 02 §8.2), and the recorder that batches the content's uses into it. */
    private val usage: io.silencelen.andvari.core.client.items.SessionUsage,
    private val usageRecorder: io.silencelen.andvari.core.client.UsageRecorderCore<io.silencelen.andvari.core.client.items.SessionUsage>,
) {
    var link: LinkAccount = link
        private set

    /** The person chose [name] on this device for the account's links (§6.3): the link engine signs it from now on. */
    fun named(name: String) {
        val l = link
        link = LinkAccount(l.origin, l.emailNorm, l.userId, l.deviceId, name, l.uvk, l.identity, l.signing, l.store, l.personalVaultId)
    }

    /** The `/sync` count of the account's live requests for the operator's help, from the last answered pull; -1 before any. */
    val recoveryRequestsCounted: Int get() = answered.recoveryRequests

    /**
     * What this opening's cache holds to send, for a composition that carries it ([QueuedCarry]). Read while the vault
     * is open, before [close].
     */
    fun queued(): QueuedCarry {
        val held = cache.heldVaults()
        val deleted = held.associate { h -> h.vault.vaultId to cache.clientState(ItemStore.HELD_DELETED_PREFIX + h.vault.vaultId) }
        return QueuedCarry(origin, userId, cache.pending(), cache.stagedDenied(), held, deleted)
    }

    /** The sync `rev` up to which this opening has read items (the item cache's cursor): a deletion's read point. */
    fun itemsReadAt(): Long = cache.cursor()

    /**
     * The server's policy forbids this copy and its wipe is owed (decided on 2026-11-17): the item engine is halted (no
     * sync, no pull, nothing sent by it), nothing new is taken in, and a change the person makes is refused with its own
     * line; the policy's run ([EnginePolicyWipe]) sends what waits once, counts, and removes the copy.
     */
    var wipeOwed: Boolean = false
        private set

    /** A forbidding policy was read while this vault is open over its copy at rest: it takes nothing new from now on. */
    fun closeForWipe() {
        wipeOwed = true
        items.halt()
        bell?.stop()
        // The content's state says so at once (the copy is being removed, with its line), not at its next change.
        content.republish()
        app.publish()
    }

    /** [carry] (what a lock kept of a copy held in memory) joins this opening's cache, before anything runs in it. */
    fun takeCarry(carry: QueuedCarry) = carry.into(cache)

    private val jobs = ArrayList<Job>()
    private var subscription: Subscription? = null
    var closed = false
        private set

    /** The event bell of this opening (spec 03 §6), while it runs; a lock stops it, a move composes a new vault and a new bell. */
    var bell: EventBell? = null
        private set

    /** A ring came that the running pull may not have seen: one more pull follows it. */
    private var ringPending = false

    /** A pull for the bell is running (or about to). */
    private var ringPulling = false

    /** Follow the content's states: every new one publishes a snapshot (its [VaultContent.state] revision). */
    fun follow(onChange: () -> Unit) {
        var first = true
        subscription = content.observe {
            if (first) first = false else if (!closed) onChange()
        }
    }

    /** Run [body] in the API's scope for as long as this vault is open; a lock cancels it. */
    fun launch(body: suspend () -> Unit) {
        if (closed) return
        val job = app.scope.launch {
            if (!closed) {
                try {
                    body()
                } catch (e: io.silencelen.andvari.core.crypto.KeysGoneException) {
                    // The vault locked while this ran: it stopped before sealing or sending anything more,
                    // and what it had not done stays queued or kept for the next unlock. That is the lock, not a failure.
                }
            }
        }
        jobs += job
        job.invokeOnCompletion { jobs -= job }
    }

    /**
     * The opening: the deferred vault records are written (design §5.4: "at the first sync, unlock or lock after the
     * interval"), then the content syncs quietly, which shows the cached copy before it asks the server.
     */
    fun start() {
        // An opening that may keep nothing at rest (the consent turned, or the policy) takes a
        // record an earlier lock kept off the disk at once, into this opening's memory; a sync sends it, a lock drops it.
        if (!keptAtRest) restoreKeptUses()
        // The person's own deletes and leaves an earlier opening sent without an answer: their departure, when this opening
        // sees the server store it, is the person's own act, not news (never "deleted by its owner").
        EngineSharedVaults.ownDepartures(app.engine.state, origin, userId).forEach { items.expectDeparture(it) }
        // A copy the server signed out (design §4.4) is read from itself only: no flush, no sync, no bell. So is a copy whose
        // wipe the server's policy calls for: its run sends what waits, once.
        if (signedOutByServer || wipeOwed) return
        launch {
            logs.flushVaultRecords()
            syncQuietly()
        }
        startBell()
    }

    /**
     * A quiet sync; after a completed one the usage ledger is flushed and pruned against the live envelopes, which a
     * completed pull makes complete (spec 02 §8.2).
     */
    private suspend fun syncQuietly() {
        val r = content.syncQuietly()
        if (r is io.silencelen.andvari.core.app.ActionResult.Ok && !closed) {
            // Uses an earlier lock kept (sealed before its wipe) join this flush, once.
            restoreKeptUses()
            usageRecorder.flushWithPrune(usage, items.liveItemIds())
            // The changes to shared vaults that wait: sent again by the general rule, and settled against this read,
            // before a screen draws them (design §3.7).
            if (!closed) app.vaultsFlow.settleWaiting(this)
        }
    }

    /**
     * The deletions that wait for the person's word and that a look in their vault's log (nothing sent) found still waiting
     * in this opening, by the hash of each deletion's signed entry: only these are asked about
     * ([io.silencelen.andvari.core.app.WaitingChange.asksForWord]). A later deletion of the same vault is another entry and
     * gets a look of its own; a hash whose deletion no longer waits is let go of at the next settle.
     */
    val askedForWord = HashSet<String>()

    /**
     * This opening of the account (one per unlock and per sign-in): a waiting change a screen was handed carries it, and an
     * act on it in another opening answers stale.
     */
    val opening: Any = Any()

    /**
     * The uses the last lock kept for this account ([keepUsesAtLock]) are opened under this opening's keys, handed to the
     * recorder and forgotten here, so they are sent once, by the flush that follows. No wait between the read and the
     * hand-over. A kept record that does not open (another key, damage) is dropped: usage is a ranking hint.
     */
    /** The usage ledger's plaintext of [sealed] under this opening's key (tests read what the server holds). */
    internal fun openUsage(sealed: String): ByteArray = usage.open(sealed)

    private fun restoreKeptUses() {
        val state = app.engine.state
        state.set(legacyKeptUsesKey(userId), null)
        val key = keptUsesKey(origin, userId)
        val sealed = state.get(key) ?: return
        val kept = try {
            io.silencelen.andvari.core.client.UsageLedger.parse(usage.open(sealed).decodeToString())
        } catch (e: io.silencelen.andvari.core.crypto.KeysGoneException) {
            // Locked meanwhile: the record stays, for the next opening.
            return
        } catch (e: Exception) {
            emptyMap()
        }
        state.set(key, null)
        usageRecorder.restore(kept)
    }

    /**
     * At a lock, BEFORE the keys are wiped: the uses recorded since the last
     * flush are taken from the recorder, sealed at once under the ledger's own key (the same seal the server holds; no
     * wait, inside the key's guarded use) and kept in this device's state, merged with any kept before, for the next
     * opening's first completed sync to send ([restoreKeptUses]). A lock never waits for the network, and nothing is
     * sealed after the wipe: a guard that already refuses (the keys went first) means the uses go. Only while this
     * opening may keep anything at rest ([keptAtRest]: the policy as read allows an offline copy and the platform
     * consents); otherwise, and for a copy the server signed out or one halted for an update, they are dropped.
     */
    private fun keepUsesAtLock() {
        val mine = usageRecorder.takeAll()
        if (mine.isEmpty() || !keptAtRest || signedOutByServer || haltedForUpdate) return
        // Keeping must still be allowed now, not only at the composition: the platform's consent and the policy as last read.
        if (!app.engine.keepsAtRest() || app.policies.get(origin)?.offlineCacheAllowed != true) return
        val state = app.engine.state
        val key = keptUsesKey(origin, userId)
        try {
            val before = state.get(key)?.let { old ->
                try {
                    io.silencelen.andvari.core.client.UsageLedger.parse(usage.open(old).decodeToString())
                } catch (e: io.silencelen.andvari.core.crypto.KeysGoneException) {
                    throw e
                } catch (e: Exception) {
                    emptyMap()
                }
            }.orEmpty()
            val merged = io.silencelen.andvari.core.client.UsageLedger.merge(before, mine)
            state.set(key, usage.seal(io.silencelen.andvari.core.client.UsageLedger.serialize(merged).encodeToByteArray()))
        } catch (e: io.silencelen.andvari.core.crypto.KeysGoneException) {
            // The keys were wiped first: nothing is sealed after the wipe, and these uses go.
        } catch (e: Exception) {
            // No personal vault key, or a store that refused: a ranking hint is never worth a failed lock.
        }
    }

    /**
     * The bell starts with the opening, over the session's own client (its guard, bearer and one refresh). A ring is a
     * dirty bit (spec 03 §6): every registered (re)open, and every ring whose `rev` is above the highest rev a pull or a
     * push of this opening was answered at ([answered]), asks for a quiet sync. A `revoked` ends the session as the
     * server's own end.
     *
     * Hostile harness H12: the rings are coalesced. The handler never waits for the sync, so the bell reads on, and the
     * rings that arrive while a sync runs cost at most one more sync after it. A ring's `rev` is the server's word only:
     * it never raises the bar later rings are measured against, so an absurdly high one costs one sync and silences no
     * honest ring after it.
     */
    private fun startBell() {
        val socket = bellSocket ?: return
        if (closed) return
        val b = EventBell(
            app.clientFor(origin), socket,
            onRing = { rev ->
                if (!closed && (rev == null || rev > answered.rev)) {
                    ringPending = true
                    if (!ringPulling) {
                        ringPulling = true
                        // In the vault's scope: a lock cancels it.
                        launch {
                            try {
                                while (ringPending && !closed) {
                                    ringPending = false
                                    syncQuietly()
                                }
                            } finally {
                                ringPulling = false
                            }
                        }
                        // A vault closed before the pull could start: nothing runs, so nothing is pulling.
                        if (closed) ringPulling = false
                    }
                }
            },
            onRevoked = { if (!closed) app.bellRevoked(origin, userId) },
        )
        bell = b
        // Engine-17 item 1: the dialer's socket says why none is open and whether one is; every change of either after
        // this point is a new snapshot ([liveUpdates], which reads them afresh). Watched before the bell starts, so no
        // change is missed; in the vault's scope, so a lock or a move ends the watch with the bell.
        if (socket is io.silencelen.andvari.core.client.net.DialedBellSocket) launch {
            combine(socket.failure, socket.connected) { f, c -> f?.kind to c }
                .distinctUntilChanged()
                .drop(1)
                .collect { if (!closed) app.publish() }
        }
        b.start(app.scope)
    }

    /**
     * This opening's live updates as the open vault shows them ([io.silencelen.andvari.core.app.LiveUpdates]): from the
     * dialer's socket when the transport gave one; a socket of another kind (a test's) says only whether the bell is
     * registered. Not running once the vault is closed or when this opening has no bell.
     */
    fun liveUpdates(): io.silencelen.andvari.core.app.LiveUpdates {
        val b = bell
        if (closed || b == null) return io.silencelen.andvari.core.app.LiveUpdates.NOT_RUNNING
        val dialed = bellSocket as? io.silencelen.andvari.core.client.net.DialedBellSocket
            ?: return io.silencelen.andvari.core.app.LiveUpdates(true, b.state == io.silencelen.andvari.core.client.items.BellState.OPEN, null)
        val connected = dialed.connected.value
        val trouble = if (connected) null else when (dialed.failure.value?.kind) {
            null -> null
            io.silencelen.andvari.core.client.net.BellFailure.Kind.ORIGIN_STOPPED -> io.silencelen.andvari.core.app.LiveUpdatesTrouble.SERVER_STOPPED
            io.silencelen.andvari.core.client.net.BellFailure.Kind.NOT_OPENED -> io.silencelen.andvari.core.app.LiveUpdatesTrouble.NOT_OPENED
            io.silencelen.andvari.core.client.net.BellFailure.Kind.TOO_LARGE -> io.silencelen.andvari.core.app.LiveUpdatesTrouble.TOO_LARGE
            io.silencelen.andvari.core.client.net.BellFailure.Kind.BROKEN -> io.silencelen.andvari.core.app.LiveUpdatesTrouble.BROKEN
        }
        return io.silencelen.andvari.core.app.LiveUpdates(true, connected, trouble)
    }

    /** The app came to the foreground: the bell's ladder goes to zero and a waiting bell dials now. */
    fun resetBell() {
        if (!closed) bell?.reset()
    }

    /** A vault-log action is about to delete or leave [vaultId]: the item engine is told, so the vault goes quietly. */
    fun beforeDeparture(vaultId: String) = items.expectDeparture(vaultId)

    /** The person's own delete or leave of [vaultId] did not happen: its departure, should it come, is said after all. */
    fun departureRefused(vaultId: String) = items.withdrawDeparture(vaultId)

    /** After a vault-log action (create, accept, leave, delete, restore): the engine re-reads its keys at a sync. */
    fun afterLogAction() = launch { syncQuietly() }

    /**
     * The content is closed, running work stops, the item engine's cache is closed (its file stays) and every vault key
     * the log engine holds in memory is wiped. No flush runs here: it would seal under keys about to go; the deferred
     * vault records are written at the next unlock and at every sync.
     */
    fun close(keepUses: Boolean = false) {
        if (closed) return
        closed = true
        bell?.stop()
        subscription?.close()
        subscription = null
        for (j in jobs.toList()) j.cancel()
        jobs.clear()
        // A lock ([keepUses]) seals the uses not yet flushed now, while the keys are still here, and keeps them for the
        // next opening ([keepUsesAtLock]); nothing is sent for the lock. Any other end drops them with the opening.
        if (keepUses) keepUsesAtLock()
        usageRecorder.clear()
        try {
            content.close()
            items.close()
        } finally {
            logs.wipeKeys()
        }
    }

    internal companion object {
        /** The cache file of [userId] at [origin]. */
        fun cacheName(app: EngineAppApi, origin: String, userId: String): String = ItemCacheNames.fileName(app.crypto, origin, userId)

        /**
         * Compose the account's engines on [open], the session the keeper holds. The cache is a file only when the
         * server's client policy, as last read, allows an offline cache; otherwise it is in memory, and a file left
         * from before is deleted (nothing is kept at rest that the server forbids; a policy never read counts as
         * forbidding).
         */
        fun compose(app: EngineAppApi, open: EstablishedSession, carry: QueuedCarry? = null, haltForUpdate: Boolean = false): EngineVault {
            val engine = app.engine
            val crypto = engine.crypto
            val origin = open.origin
            val userId = open.userId
            val account = open.account
            val client = app.clientFor(origin)
            val store = StoredAccountState(userId, account.uvk, client, crypto, engine.state)
            // The name kept from this device's registration; empty when the account was made elsewhere (no answer can carry it).
            val link = LinkAccount.of(open, app.displayName(origin, userId), store)
            val currency = ContactCurrency(engine.state, crypto, origin, userId)
            val contacts = AccountContactBook(link, currency, passwordOnly = open.how == SessionHow.PASSWORD, clock = engine.clock)
            val rows = VaultRows(crypto)
            val logHost = object : VaultLogHost {
                override fun grantRow(vaultId: String): SyncGrant? = rows.grantRow(vaultId)
                override fun isCurrentContact(userId: String, identityPub: String): Boolean = contacts.currentFor(userId, identityPub) != null
                override fun currentContact(userId: String): Pair<String, Boolean>? {
                    val r = store.local().contacts[userId] ?: return null
                    return if (contacts.currentFor(userId, r.identityPub) != null) r.identityPub to r.compared else null
                }
                override fun labelFor(userId: String, identityPub: String): String? = contacts.currentFor(userId, identityPub)?.labelText
                override fun vaultName(vaultId: String, vk: ByteArray): String? = rows.vaultName(vaultId, vk)
                override fun sealMeta(vaultId: String, vk: ByteArray, name: String): String = rows.sealMeta(vaultId, vk, name)
                override fun serverOwnerName(vaultId: String): String? = null
            }
            val checkpoints = BundleCheckpoints(engine.state)
            val logs = StoredVaultLogs(
                userId, account.signing, account.identity, account.uvk, client, crypto, engine.state, store, logHost, engine.clock,
                { vaultId -> checkpoints.get(origin, userId, vaultId) },
            )
            // A cold start, or a server this device may not dial, reopens adopted keys only and sends nothing.
            val keys = SessionVaultKeys(account, logs, rows, engine.state) { app.keeper.mayDial(origin) }
            // What every sync's chain check finds reaches the screen while signed in.
            val gate = PinnedOriginGate(DelegatingTrust { app.trust }, origin) { s -> app.instancePart.chainChecked(origin, s) }
            // Read once for this composition; the content's host reads it again at every call. The platform's own
            // consent counts as well (the desktop's "keep me signed in").
            // A copy whose wipe the policy calls for is opened as it is, at rest, halted, for the policy's run: nothing of it
            // is removed before the run has counted it (decided on 2026-11-17). A copy already counted is not opened again.
            val owed = app.policyWipe.owed(origin, userId)
            // A copy that cannot be opened is left as it is (the run counts it as "cannot tell"); this opening is in memory.
            val owedCache = if (owed) engine.cacheFiles?.let { f -> runCatching { f.open(cacheName(app, origin, userId), userId) }.getOrNull() } else null
            val atRest = owedCache != null || (!owed && app.policies.get(origin)?.offlineCacheAllowed == true && engine.keepsAtRest())
            app.noteHeld(origin, userId)
            val cache = owedCache ?: if (owed) InMemoryVaultCache() else cacheFor(app, origin, userId, atRest, carry)
            // Attachments stay unbound until the session hands out a guarded raw-body channel (no bearer leaves the keeper).
            val answered = AnsweredRev()
            // A vault whose deletion by "Move everything" is signed and waiting is closed for writing by the content's own
            // mark (EngineSharedVaults.closeWaiting), from the moment the deletion is signed; the item engine's keys are
            // the keys as served.
            val items = ItemEngine(AnsweredRev.Watch(WireItemTransport(client, null), answered), keys, gate, cache, userId, crypto, engine.clock)
            // Signed out by the server (design §4.4): the copy is served read-only, nothing is sent or written.
            val byServer = app.keeper.session?.let { it.origin == origin && it.userId == userId && it.endedByServer } == true
            // "Update required": read-only too, the same standing, until it clears.
            if (byServer || haltForUpdate || owed) items.halt()
            // The usage ledger (spec 02 §8.2): the content records each release of a secret, batched into one sealed blob
            // per debounce; nothing is fetched or stored while the item engine is halted, or once this opening closed.
            var self: EngineVault? = null
            val usage = io.silencelen.andvari.core.client.items.SessionUsage(client, keys, crypto, userId) { items.halted }
            val usageRecorder = io.silencelen.andvari.core.client.UsageRecorderCore<io.silencelen.andvari.core.client.items.SessionUsage>(
                app.scope, USAGE_DEBOUNCE_MS, USAGE_FLUSH_MS, { usage.takeIf { self?.closed == false } }, { it },
            )
            val host = object : ContentHost {
                override fun usageLedger(): io.silencelen.andvari.core.client.UsageRecorderCore.Transport = usage
                override fun recordUse(itemId: String, atMs: Long) = usageRecorder.record(itemId, atMs)
                override fun wallMs(): Long = engine.clock()
                override fun attachmentLimits(): AttachmentLimitsView {
                    val p = app.policies.get(origin)
                    return AttachmentRules.limits(p?.attachmentMaxBytes?.takeIf { it > 0 }, p?.itemAttachmentsMaxBytes?.takeIf { it > 0 })
                }
                override fun origin(): String = origin
                override fun userId(): String = userId
                override fun accountId(): String = account.accountId(crypto)
                override fun backupKdfParams(): KdfParams? = app.policies.get(origin)?.kdfParams
                override fun offlineCacheAllowed(): Boolean = app.policies.get(origin)?.offlineCacheAllowed == true
                override fun removingForPolicy(): Boolean = self?.wipeOwed == true
                override fun openInvitationName(vaultId: String): String? = app.openInvitationName(vaultId)
            }
            // What a lock cuts short is kept sealed to the account in the process's stores, which outlive the lock. A copy
            // owed to the policy's run keeps its records where they are, for the run to count.
            // The platform's own records are used wherever the server's policy allows them, also with the platform's consent
            // to keep data switched off: such a platform keeps them in memory then (the desktop carries them there at the
            // switch-off), so this opening reads what was carried and finishes it.
            val allowed = app.policies.get(origin)?.offlineCacheAllowed == true
            val keeping = if (owed) app.stores.keepingForWipe(account, origin) else app.stores.keeping(account, origin, allowed)
            return EngineVault(
                app, origin, userId, link, contacts, store, logs, items, EngineVaultContent(items, crypto, host, keeping), rows,
                // A copy the server signed out rings no bell; otherwise a socket for THIS origin, asked anew at every opening.
                account.genesis.fields.personalVaultId, atRest, if (byServer || haltForUpdate || owed) null else engine.transport.bellSocket(origin), byServer,
                cache, haltForUpdate, answered, usage, usageRecorder,
            ).also {
                self = it
                it.wipeOwed = owed
            }
        }

        /** The usage ledger's batching: one store per this many ms of uses at most (UsageRecorderCore's debounce). */
        const val USAGE_DEBOUNCE_MS = 15_000L

        /** The bound on a teardown flush (UsageRecorderCore.flushForSession; unused here: a lock seals and keeps instead). */
        const val USAGE_FLUSH_MS = 2_000L

        /**
         * Where a lock keeps an account's unsent uses, sealed under the ledger's key, until the next opening sends them:
         * by server and account, so an account of another server that has the same id never
         * opens, overwrites or deletes it.
         */
        fun keptUsesKey(origin: String, userId: String): String = "ovh.usage.kept|$origin|$userId"

        /** The key the record had before (by account id alone): never read, only removed. */
        fun legacyKeptUsesKey(userId: String): String = "ovh.usage.kept|$userId"

        /**
         * The cache of a composition: the file while [atRest], memory otherwise (a file left from before is deleted).
         * A memory cache starts with what [carry] brought from the cache it replaces, in the same order.
         */
        private fun cacheFor(app: EngineAppApi, origin: String, userId: String, atRest: Boolean, carry: QueuedCarry?): VaultCache {
            val files = app.engine.cacheFiles
            if (files != null && atRest) return files.open(cacheName(app, origin, userId), userId)
            val memory = InMemoryVaultCache()
            carry?.into(memory)
            // Only the platform's consent turned off (the policy allows a copy) removes the file here, after the carry, and
            // under the lock every wipe takes. A policy that forbids the copy, or one never read, removes nothing here:
            // that is the policy's run's, which counts the copy first (decided on 2026-11-17).
            if (files != null && app.policies.get(origin)?.offlineCacheAllowed == true && !app.engine.keepsAtRest()) {
                app.policyWipe.lock.now { files.delete(cacheName(app, origin, userId)) }
            }
            return memory
        }
    }
}

/**
 * What a vault's cache holds to send, carried into the cache of the composition that replaces it when its copy may no
 * longer stay at rest (the server's policy or the platform's consent turned): the queued changes in order, the changes
 * the server denied that wait for a pull to decide their fate, and the held vaults with their parked edits, each with
 * the record of the deletions served for its items (spec 02 §10.6), which goes wherever its copy goes. The items, the
 * cursor and the replay records are not carried: the new cache starts from the server.
 */
internal class QueuedCarry(
    val origin: String,
    val userId: String,
    val pending: List<io.silencelen.andvari.core.model.Mutation>,
    val staged: List<io.silencelen.andvari.core.model.Mutation>,
    val held: List<io.silencelen.andvari.core.client.HeldVaultRecord>,
    /** Each held vault's record of served deletions as its cache kept it, by vault id (null: none). */
    val heldDeleted: Map<String, String?> = emptyMap(),
) {
    fun into(cache: VaultCache) {
        cache.atomically {
            for (m in pending) cache.enqueue(m)
            for (m in staged) {
                cache.enqueue(m)
                cache.markStagedDenied(m.mutationId)
            }
            for (h in held) {
                cache.putHeld(h)
                // The copy's own record, or none: a record the new cache held for that vault is not this copy's.
                cache.setClientState(ItemStore.HELD_DELETED_PREFIX + h.vault.vaultId, heldDeleted[h.vault.vaultId])
            }
        }
    }
}

/**
 * The highest `rev` a pull or a push of one opening was answered at: the bar the event bell's rings are measured
 * against ([EngineVault]'s ring handler). Only answers to this device's own requests move it; a ring's own `rev` never
 * does (hostile harness H12: an absurd ring would otherwise silence every honest one after it).
 */
internal class AnsweredRev {
    @kotlin.concurrent.Volatile
    var rev: Long = -1L
        private set

    fun saw(r: Long) {
        if (r > rev) rev = r
    }

    /**
     * The account's live requests for the operator's help, as the last answered pull counted them (spec 03 §4, §18.3:
     * `recoveryRequests`); -1 before any. The server's word: a hint to read the list, never a verdict.
     */
    @kotlin.concurrent.Volatile
    var recoveryRequests: Int = -1
        private set

    /** [inner], noting the rev of every pull and push it answers. */
    class Watch(private val inner: io.silencelen.andvari.core.client.items.ItemTransport, private val answered: AnsweredRev) :
        io.silencelen.andvari.core.client.items.ItemTransport by inner {
        override suspend fun pull(since: Long): io.silencelen.andvari.core.client.net.WireResult<io.silencelen.andvari.core.model.wire.SyncResponse> =
            inner.pull(since).also {
                if (it is io.silencelen.andvari.core.client.net.WireResult.Ok) {
                    answered.saw(it.value.rev)
                    answered.recoveryRequests = it.value.recoveryRequests.coerceAtLeast(0)
                }
            }

        override suspend fun push(mutations: List<io.silencelen.andvari.core.model.wire.Mutation>): io.silencelen.andvari.core.client.net.WireResult<io.silencelen.andvari.core.model.wire.PushResponse> =
            inner.push(mutations).also { if (it is io.silencelen.andvari.core.client.net.WireResult.Ok) answered.saw(it.value.rev) }
    }
}
