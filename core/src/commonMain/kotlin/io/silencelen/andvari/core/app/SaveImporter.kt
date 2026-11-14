package io.silencelen.andvari.core.app

import io.silencelen.andvari.core.client.Account
import io.silencelen.andvari.core.client.HouseholdCopy
import io.silencelen.andvari.core.client.ItemDoc
import io.silencelen.andvari.core.client.LoginData
import io.silencelen.andvari.core.client.OriginCanon
import io.silencelen.andvari.core.client.PasswordHistoryEntry
import io.silencelen.andvari.core.client.SaveOutcome
import io.silencelen.andvari.core.client.VaultItem
import io.silencelen.andvari.core.client.autofill.UriMatch
import io.silencelen.andvari.core.client.session.Clocks
import io.silencelen.andvari.core.client.session.VaultSession
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.CryptoProvider
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.json.Json
import kotlin.coroutines.cancellation.CancellationException

/** How a save or an undo the person asked for ended. */
internal sealed interface ImportResult {
    /** Written; [queuedOffline] when the vault queued it for the next sync. */
    data class Done(val queuedOffline: Boolean) : ImportResult

    /** There was nothing to do it to (already gone, or the vault locked). */
    data object Gone : ImportResult

    data class Failed(val message: String) : ImportResult
}

/**
 * The app's side of the extensions' save queue (design 2026-11-09, "Saving"): it publishes the key the extensions seal
 * to, opens what they queued, and saves it.
 *
 * The person already agreed to each save where it was captured (owner decision 2026-11-11), so what can be saved is
 * saved without a second tap. But the queue is a directory any process in the App Group can write, so an entry is
 * never more than a proposal, and what is automatic is bounded:
 *  - a NEW login is added to the personal vault;
 *  - a new password replaces an existing one only in the PERSONAL vault (never a vault shared with the person, and
 *    never one they share out), for the login with the same host, port, scheme and username, and only when the capture
 *    is newer than that login's last change, its scheme is known, and no earlier automatic replace of that login is
 *    still listed (one replace per login until the person has dismissed or undone it); the password it replaces is
 *    kept in the login's history;
 *  - at most [MAX_AUTO_PER_RUN] entries are applied per unlock or return to the foreground, and an entry that cap
 *    held back is never applied by itself later (its id is kept, in app-private storage): it waits for the person;
 *  - every automatic save is listed, survives a lock (in app-private storage, sealed to the account), and can be
 *    undone one by one or all at once until the person dismisses the list.
 * Everything else stays listed with its reason, to be saved or discarded by hand.
 *
 * A capture's time is the capturing extension's own word, so the freshness rule protects against a stale HONEST capture
 * (an old entry replayed by the system, a first attempt before a corrected password); it stops no forger. The bounds
 * that do are the personal-vault-only replace, one listed replace per login, the cap with its kept holds, and the undo.
 *
 * One mutex serializes a sync of the queue, an automatic apply, a manual save, an undo, a discard, a dismissal and the
 * person's own edits and deletions ([exclusive]): they all read the vault, decide, and write across suspension points.
 */
internal class SaveImporter(
    private val queue: SaveQueueStore,
    /** The applied list, in app-private storage (never the App Group). */
    private val appliedStore: FillSnapshotStore,
    private val clocks: Clocks,
    private val crypto: () -> CryptoProvider,
    /** Publish what is listed now; [unreadable] when entries had to be removed unread. */
    private val publish: (pending: List<PendingSaveView>, applied: List<AppliedSaveView>, unreadable: Boolean) -> Unit,
    /** The vault was written: refresh the list and whatever mirrors it. */
    private val wrote: () -> Unit,
    /** Entries of the list an earlier version wrote, which this one cannot read, were removed: how many (round-10 review 3). */
    private val dropped: (Int) -> Unit = {},
) {
    val enabled: Boolean get() = queue !== SaveQueueStore.None

    private val mutex = Mutex()

    /**
     * Bumped by every [locked] (and so by [dropAll]): a lock clears memory at once and never waits for the operation
     * holding [mutex]. That operation (an automatic save whose write fails when the engine closes, say) must then
     * persist nothing: what it would store was read for a session that has ended, from maps the lock has emptied.
     */
    private var generation = 0

    /** The [generation] the operation holding [mutex] began in. */
    private var opGeneration = -1

    /**
     * Run [block] holding [mutex], as an operation of the session it was asked for in: the generation is read when the
     * operation is asked for, before it waits for the mutex, so one that waited out a lock writes nothing either.
     */
    private suspend fun <T> op(block: suspend () -> T): T {
        val asked = generation
        return mutex.withLock {
            opGeneration = asked
            block()
        }
    }

    /** Whether the operation holding [mutex] still belongs to the session it began in. */
    private val opAlive: Boolean get() = opGeneration == generation

    /** Why the stored list is written. Only an emptiness the person caused, or one checked against the vault, removes it. */
    private enum class Persist { CHANGE, PERSON, VERIFIED }
    private val pending = LinkedHashMap<String, Pending>()
    private val applied = LinkedHashMap<String, AppliedRecord>()
    private var appliedLoaded = false

    /** Queue entries the per-run cap held back: they stay manual for good. Kept with the applied list. */
    private val held = LinkedHashSet<String>()

    /** How the vault took the last write: applied, or queued for the next sync. */
    private var lastOutcome = SaveOutcome.APPLIED

    private class Pending(val login: CapturedLogin, var target: VaultItem?, var reason: String? = null)

    /**
     * One automatic save, for the list and its undo. Kept sealed to the account (it names the password it wrote, so an
     * undo can tell whether the login changed since), in app-private storage.
     */
    @Serializable
    private data class AppliedRecord(
        /**
         * The record's own id, minted here when the save is written: what the list, its Undo and Undo all name. Never
         * the queue entry's id: a later capture, or a forged one, can reuse an entry's name, and must not take another
         * save's Undo away. (In a record from before this was kept, it is the entry's id.)
         */
        val id: String,
        val site: String,
        val username: String,
        val itemId: String,
        /** The name of the login it replaced the password of; null when it added the login. */
        val replacedName: String?,
        val password: String,
        /** A replace put the old password in the history (false: there was none to keep). */
        val keptOld: Boolean,
        val appliedAtMs: Long,
        /**
         * Stored BEFORE the vault is written, and cleared once the write is known to have happened. A record that is
         * still an intent at the next unlock is settled by looking at the vault ([settleLocked]); it is never listed.
         */
        val intent: Boolean = false,
        /** When the capture says it was made (0 in a record from before this was kept). */
        val capturedAtMs: Long = 0,
        /** A digest of the login as a save ADDED it: an undo removes the login only while it is still exactly that. */
        val docDigest: String? = null,
        /** The queue entry the save came from, removed once the write is settled ("" in a record from before: [id] is it). */
        val queueId: String = "",
    ) {
        val entry: String get() = queueId.ifEmpty { id }
    }

    /** What is kept at rest: the records, each sealed to the account, and the ids the cap held back. */
    @Serializable
    private data class Stored(val records: List<String> = emptyList(), val held: List<String> = emptyList())

    private fun digest(doc: ItemDoc): String = Bytes.toB64(crypto().sha256(json.encodeToString(ItemDoc.serializer(), doc).encodeToByteArray()))

    /** An automatic replace of this login is still listed: no second one until the person dismissed or undid it. */
    private fun replaceListed(itemId: String) = applied.values.any { !it.intent && it.replacedName != null && it.itemId == itemId }

    /** Run [block] alone with respect to every save, undo and sync here: the person's own edit or deletion of an item. */
    suspend fun <T> exclusive(block: suspend () -> T): T = op(block)

    // ---- what a capture is ----

    private enum class Scheme { HTTP, HTTPS, UNKNOWN }

    private fun schemeOf(site: String): Scheme {
        val s = site.trim()
        return when {
            s.startsWith("http://", ignoreCase = true) -> Scheme.HTTP
            s.startsWith("https://", ignoreCase = true) -> Scheme.HTTPS
            else -> Scheme.UNKNOWN // a bare domain (the system's `.domain` service identifier): it may be either
        }
    }

    /** A saved address has no scheme only by omission, and then means https. */
    private fun savedScheme(uri: String) = if (schemeOf(uri) == Scheme.HTTP) Scheme.HTTP else Scheme.HTTPS

    /** The explicit port of an address, or null for the scheme's default. */
    private fun portOf(address: String): String? {
        val authority = address.trim().substringAfter("://").takeWhile { it != '/' && it != '?' && it != '#' }.substringAfterLast('@')
        val port = if (authority.startsWith("[")) authority.substringAfter("]", "").removePrefix(":") else authority.substringAfter(':', "")
        return port.takeIf { it.isNotEmpty() && it.all(Char::isDigit) && it != "443" && it != "80" }
    }

    /** Whether [item] is a login for the capture's username on its host and port (whatever the scheme). */
    private fun sameSite(item: VaultItem, captured: CapturedLogin): Boolean {
        val host = UriMatch.normalizeHost(captured.site) ?: return false
        val login = item.doc.login ?: return false
        return login.username.orEmpty() == captured.username && login.uris.any { UriMatch.normalizeHost(it) == host && portOf(it) == portOf(captured.site) }
    }

    /**
     * Whether [item] is the same login as the capture: [sameSite], and on the same transport. A capture from a
     * plain-http page is never the https login of that host (and the reverse). A capture with no scheme matches
     * either, and is for that reason never applied over an existing login by itself.
     */
    private fun sameLogin(item: VaultItem, captured: CapturedLogin): Boolean {
        val scheme = schemeOf(captured.site)
        val host = UriMatch.normalizeHost(captured.site) ?: return false
        return sameSite(item, captured) && item.doc.login.orEmpty().uris.any {
            UriMatch.normalizeHost(it) == host && portOf(it) == portOf(captured.site) && (scheme == Scheme.UNKNOWN || savedScheme(it) == scheme)
        }
    }

    private fun LoginData?.orEmpty(): LoginData = this ?: LoginData()

    private fun key(c: CapturedLogin) = "${UriMatch.normalizeHost(c.site)}|${portOf(c.site)}|${schemeOf(c.site)}|${c.username}"

    /** The login in the PERSONAL vault a save of [captured] would update, or null: a save then adds a login. */
    private fun personalTarget(logins: List<VaultItem>, captured: CapturedLogin, account: Account): VaultItem? =
        logins.firstOrNull { account.personalVaultId.isNotEmpty() && it.vaultId == account.personalVaultId && sameLogin(it, captured) }

    private fun logins(live: VaultSession.Unlocked) = live.engine.items().filter { it.doc.type == "login" }

    // ---- the queue ----

    /**
     * Publish the key, read the queue, and (with [apply]) save what may be saved by itself. [origin] is the server the
     * app dials; with [allowed] false (its policy forbids keeping data on the device) no key is published and the queue
     * and the applied list are emptied.
     */
    suspend fun sync(live: VaultSession.Unlocked, origin: String, allowed: Boolean, apply: Boolean, stillLive: () -> Boolean) = op {
        if (!enabled || !stillLive()) return@op
        if (!allowed) {
            dropAll()
            return@op
        }
        // The key the extensions seal to is this account's, whatever the file said: a published key that is not ours
        // (replaced by something else in the App Group, or left by another account) is put right here. What was
        // sealed to it in between cannot be read by this account, and could be read by whoever replaced it.
        val publication = SaveQueue.publication(origin, live.account)
        val published = queue.publication()
        if (published == null || !published.contentEquals(publication)) queue.publish(publication)
        loadApplied(live)
        settleLocked(live)

        val now = clocks.wallMs()
        val vault = logins(live)
        var unreadable = false
        val opened = ArrayList<Pair<String, CapturedLogin>>()
        for ((id, bytes) in queue.entries()) {
            val login = SaveQueue.open(live.account, origin, bytes, now)
            if (login == null) {
                unreadable = true
                queue.remove(id)
            } else {
                opened += id to login
            }
        }
        // Oldest first, whatever their ids: the newest capture of a login is the one that counts, and an older one for
        // the same login (a replayed entry, a corrected password's first attempt) is dropped.
        opened.sortBy { it.second.capturedAtMs }
        val newest = HashMap<String, Long>()
        for ((_, login) in opened) newest[key(login)] = login.capturedAtMs
        val before = HashMap(pending)
        pending.clear()
        for ((id, login) in opened) {
            // Capture time against capture time (a record from before that was kept has only when it was applied).
            val superseded = login.capturedAtMs < (newest[key(login)] ?: 0L) ||
                applied.values.any { !it.intent && it.site == login.site && it.username == login.username && (if (it.capturedAtMs > 0) it.capturedAtMs else it.appliedAtMs) >= login.capturedAtMs }
            val already = vault.any { sameLogin(it, login) && it.doc.login?.password == login.password }
            if (superseded || already) {
                queue.remove(id)
                continue
            }
            // An entry already listed keeps its reason; one that was mid-apply when this sync began is judged again,
            // and so is one that only waited for a personal vault, once there is one.
            val was = before[id]
            val waitedForVault = was?.reason == HouseholdCopy.NO_PERSONAL_VAULT || was?.reason == PERSONAL_UNCONFIRMED || was?.reason == PERSONAL_RECORD_MISSING
            val reason = if (id in held) TOO_MANY else was?.reason?.takeUnless { waitedForVault && live.account.personalStatus == Account.PersonalStatus.CONFIRMED }
            pending[id] = Pending(login, personalTarget(vault, login, live.account), reason)
        }
        // A hold lasts as long as its entry does.
        if (held.retainAll(pending.keys)) storeApplied(live, Persist.VERIFIED)
        if (apply) applyLocked(live, stillLive)
        vaultNames = { itemId ->
            runCatching { live.engine.item(itemId)?.let { item -> live.engine.vaultInfos().firstOrNull { it.vaultId == item.vaultId }?.name ?: "a vault this device cannot name" } }.getOrNull()
        }
        if (stillLive()) publish(pendingViews(), appliedViews(), unreadable)
    }

    /** Why [p] is not saved by itself, or null when it may be. */
    private fun refusal(p: Pending, vault: List<VaultItem>, account: Account, now: Long, appliedThisRun: Int): String? {
        val captured = p.login
        val target = p.target
        return when {
            UriMatch.normalizeHost(captured.site) == null -> NOT_A_SITE
            // While the personal-vault question is open (in any of its states) nothing is written by itself: the
            // vault this device would use may not be the one the person, or their other devices, mean.
            // WITHHELD and UNREADABLE_CACHED have nothing for the person to confirm: the server's record is missing or
            // unreadable this time, and the notice says so. The reason here says the same, not "confirm above".
            account.personalStatus == Account.PersonalStatus.WITHHELD || account.personalStatus == Account.PersonalStatus.UNREADABLE_CACHED -> PERSONAL_RECORD_MISSING
            account.personalStatus != Account.PersonalStatus.CONFIRMED -> PERSONAL_UNCONFIRMED
            captured.capturedAtMs > now + CLOCK_SKEW_MS -> FROM_THE_FUTURE
            target == null && vault.any { it.vaultId != account.personalVaultId && sameSite(it, captured) } -> SHARED_MATCH
            target == null && schemeOf(captured.site) == Scheme.UNKNOWN && vault.any { sameSite(it, captured) } -> SCHEME_UNKNOWN
            target == null && account.personalVaultId.isEmpty() -> HouseholdCopy.NO_PERSONAL_VAULT
            target != null && schemeOf(captured.site) == Scheme.UNKNOWN -> SCHEME_UNKNOWN
            target != null && replaceListed(target.itemId) -> ALREADY_REPLACED
            // A capture no newer than the login's last change would roll its password back (a replayed entry).
            target != null && captured.capturedAtMs <= target.updatedAt -> OLDER_THAN_LOGIN
            appliedThisRun >= MAX_AUTO_PER_RUN -> TOO_MANY
            else -> null
        }
    }

    private suspend fun applyLocked(live: VaultSession.Unlocked, stillLive: () -> Boolean) {
        var appliedThisRun = 0
        var wroteAny = false
        for ((id, p) in pending.toList()) {
            if (!stillLive()) return
            if (p.reason != null) continue
            val vault = logins(live)
            p.target = personalTarget(vault, p.login, live.account)
            p.reason = refusal(p, vault, live.account, clocks.wallMs(), appliedThisRun)
            if (p.reason == TOO_MANY && held.add(id)) storeApplied(live, Persist.CHANGE) // kept: never applied by itself later
            if (p.reason != null) continue
            val record = try {
                write(live, id, p)
            } catch (c: CancellationException) {
                throw c
            } catch (t: Throwable) {
                p.reason = HouseholdCopy.forError(t)
                continue
            }
            if (!stillLive()) return // the stored intent is settled at the next unlock
            finish(live, id, record)
            appliedThisRun++
            wroteAny = true
        }
        if (wroteAny) wrote()
    }

    /** The write happened: the entry ([queueId]) leaves the queue and the record is listed under its own id. */
    private fun finish(live: VaultSession.Unlocked, queueId: String, record: AppliedRecord) {
        // A session that ended meanwhile keeps its entry and its stored intent: the next unlock settles them.
        if (!opAlive) return
        queue.remove(queueId)
        pending.remove(queueId)
        held.remove(queueId)
        applied[record.id] = record.copy(intent = false)
        storeApplied(live, Persist.CHANGE)
    }

    /**
     * Bring the stored list in line with the vault. Nothing is ever written to the vault from a record: a login this
     * device no longer shows was removed (here, on another device, or from the web's trash), and the cache keeps no
     * trace of a removed login, so "missing" can never be told from "deleted" and is always taken as deleted.
     *  - A record whose login is gone is dropped: there is nothing left to undo.
     *  - An intent (stored before a write that a lock or a crash cut short) becomes a listed record when the vault
     *    shows the write happened, and its queue entry goes. Otherwise it is dropped and the entry, still in the
     *    queue, is judged again like any other.
     */
    private fun settleLocked(live: VaultSession.Unlocked) {
        var changed = false
        for ((id, record) in applied.toList()) {
            val item = live.engine.item(record.itemId)
            when {
                record.intent && item != null && (record.replacedName == null || item.doc.login?.password == record.password) -> {
                    queue.remove(record.entry)
                    applied[id] = record.copy(intent = false)
                    changed = true
                }
                record.intent || item == null -> {
                    applied.remove(id)
                    changed = true
                }
            }
        }
        if (changed) storeApplied(live, Persist.VERIFIED)
    }

    /**
     * Write one capture to the vault: the target's new password, or a new login under an id minted here. The record
     * is stored as an intent first, so a lock between the write and the bookkeeping cannot leave a write nothing lists.
     * A write that fails takes its intent with it.
     */
    private suspend fun write(live: VaultSession.Unlocked, queueId: String, p: Pending): AppliedRecord {
        val captured = p.login
        val host = UriMatch.normalizeHost(captured.site) ?: error("not a site")
        val now = clocks.wallMs()
        val target = p.target
        val old = target?.doc?.login.orEmpty().password.orEmpty()
        val keep = target != null && old.isNotEmpty() && old != captured.password
        // The id of a new login is minted here, so the undo names exactly the login this save added.
        val itemId = target?.itemId ?: Bytes.uuidV4FromBytes(crypto().randomBytes(16))
        val address = (if (schemeOf(captured.site) == Scheme.HTTP) "http://" else "https://") + host + (portOf(captured.site)?.let { ":$it" } ?: "")
        val doc = ItemDoc(type = "login", name = UriMatch.normalizeHostUnicode(captured.site) ?: host, login = LoginData(username = captured.username, password = captured.password, uris = listOf(address)))
        val record = AppliedRecord(
            Bytes.uuidV4FromBytes(crypto().randomBytes(16)), captured.site, captured.username, itemId, target?.doc?.name, captured.password, keep, now,
            intent = true, capturedAtMs = captured.capturedAtMs, docDigest = if (target == null) digest(doc) else null, queueId = queueId,
        )
        applied[record.id] = record
        storeApplied(live, Persist.CHANGE)
        try {
            if (target == null) {
                lastOutcome = live.engine.saveWithUploads(null, doc, emptyList(), null, null, itemId)
                // Never "saved" on the save's word alone: the login must be in the vault the list is drawn from.
                check(live.engine.item(itemId) != null) { "the vault did not keep the new login" }
            } else {
                val login = target.doc.login.orEmpty()
                // The history keeps each earlier password once, newest last, and no more than HISTORY_MAX of them.
                val history = if (keep) (login.passwordHistory.filter { it.password != old } + PasswordHistoryEntry(old, now)).takeLast(HISTORY_MAX) else login.passwordHistory
                lastOutcome = live.engine.save(target.itemId, target.doc.copy(login = login.copy(password = captured.password, passwordHistory = history)), target.vaultId)
            }
        } catch (c: CancellationException) {
            throw c // the intent stays stored: the next unlock looks at the vault and settles it
        } catch (t: Throwable) {
            applied.remove(record.id)
            storeApplied(live, Persist.CHANGE) // nothing, once the session has ended: the intent stays for the next unlock
            throw t
        }
        return record
    }

    // ---- by hand ----

    fun password(id: String): String? = pending[id]?.login?.password

    /**
     * Save one listed capture because the person said so: the new password of the personal-vault login the row named,
     * or a new login of their own. What the row showed is what is written: if the login it named changed or went, or
     * one appeared, nothing is written and the row is shown again as the vault is now.
     */
    suspend fun confirm(live: VaultSession.Unlocked, id: String, stillLive: () -> Boolean): ImportResult = op {
        val p = pending[id] ?: return@op ImportResult.Gone
        val vault = logins(live)
        val now = personalTarget(vault, p.login, live.account)
        if (now?.itemId != p.target?.itemId || now?.doc != p.target?.doc) {
            p.target = now
            p.reason = TARGET_CHANGED
            publish(pendingViews(), appliedViews(), false)
            return@op ImportResult.Failed(TARGET_CHANGED)
        }
        if (now == null && live.account.personalVaultId.isEmpty()) {
            return@op ImportResult.Failed(if (live.account.personalStatus != Account.PersonalStatus.CONFIRMED) PERSONAL_UNCONFIRMED else HouseholdCopy.NO_PERSONAL_VAULT)
        }
        if (UriMatch.normalizeHost(p.login.site) == null) return@op ImportResult.Failed(NOT_A_SITE)
        val record = write(live, id, p)
        if (!stillLive()) return@op ImportResult.Gone
        finish(live, id, record)
        wrote()
        publish(pendingViews(), appliedViews(), false)
        ImportResult.Done(queuedOffline = lastOutcome == SaveOutcome.QUEUED)
    }

    /** Discard one listed capture: it leaves the queue and nothing is written. */
    suspend fun discard(live: VaultSession.Unlocked, id: String) = op {
        queue.remove(id)
        pending.remove(id)
        if (held.remove(id)) storeApplied(live, Persist.PERSON)
        publish(pendingViews(), appliedViews(), false)
    }

    // ---- undo ----

    /**
     * Take back one save, exactly: a login it added is removed only if it is still as it was added, and a replaced
     * password is put back (and its history entry taken out again) only if the login still has the password this
     * save wrote and that history entry on top. Anything else has been changed since, and is left alone.
     */
    suspend fun undo(live: VaultSession.Unlocked, id: String, stillLive: () -> Boolean): ImportResult = op {
        val result = undoLocked(live, id)
        if (result is ImportResult.Done && stillLive()) {
            storeApplied(live, Persist.PERSON)
            wrote()
            publish(pendingViews(), appliedViews(), false)
        }
        result
    }

    /** [undo] for every listed save; a failure names how many could not be undone. */
    suspend fun undoAll(live: VaultSession.Unlocked, stillLive: () -> Boolean): ImportResult = op {
        var failed = 0
        var queued = false
        for (id in applied.keys.toList()) {
            when (val r = undoLocked(live, id)) {
                is ImportResult.Done -> queued = queued || r.queuedOffline
                else -> failed++
            }
            if (!stillLive()) return@op ImportResult.Gone
        }
        storeApplied(live, Persist.PERSON)
        wrote()
        publish(pendingViews(), appliedViews(), false)
        if (failed == 0) ImportResult.Done(queued) else ImportResult.Failed(if (failed == 1) UNDO_CHANGED else "$failed of these have changed since, so they were not undone.")
    }

    private suspend fun undoLocked(live: VaultSession.Unlocked, id: String): ImportResult {
        val record = applied[id] ?: return ImportResult.Gone
        val item = live.engine.item(record.itemId)
        val login = item?.doc?.login
        if (item == null || login == null || login.password.orEmpty() != record.password || login.username.orEmpty() != record.username) return ImportResult.Failed(UNDO_CHANGED)
        val outcome = if (record.replacedName == null) {
            // Removing is not something an undo can take back: the login must still be exactly what the save added,
            // in every field (a note, a code or another address added since is the person's work).
            if (record.docDigest != null && digest(item.doc) != record.docDigest) return ImportResult.Failed(UNDO_EDITED)
            live.engine.remove(record.itemId)
        } else {
            val top = login.passwordHistory.lastOrNull()
            if (record.keptOld && top?.retiredAt != record.appliedAtMs) return ImportResult.Failed(UNDO_CHANGED)
            val restored = if (record.keptOld) login.copy(password = top!!.password, passwordHistory = login.passwordHistory.dropLast(1)) else login.copy(password = null)
            live.engine.save(item.itemId, item.doc.copy(login = restored), item.vaultId)
        }
        applied.remove(id)
        return ImportResult.Done(outcome == SaveOutcome.QUEUED)
    }

    /**
     * The person deleted [itemId] in this app: a save that added it has nothing left to undo, and must never add it
     * again as a login that "went missing". Called inside [exclusive], with the deletion.
     */
    fun itemDeletedLocked(live: VaultSession.Unlocked, itemId: String) {
        val ids = applied.filterValues { it.itemId == itemId }.keys
        if (ids.isEmpty()) return
        ids.forEach(applied::remove)
        storeApplied(live, Persist.PERSON)
        publish(pendingViews(), appliedViews(), false)
    }

    /** The list has been read: it goes, in memory and in storage, and with it the undo from here. */
    suspend fun dismiss(live: VaultSession.Unlocked) = op {
        applied.clear()
        storeApplied(live, Persist.PERSON)
        publish(pendingViews(), appliedViews(), false)
    }

    // ---- lifetime ----

    /**
     * The vault locked: nothing opened stays in memory, and nothing is persisted (an operation still running writes
     * nothing from here, [generation]). The stored list is read again at the next unlock.
     */
    fun locked() {
        generation++
        pending.clear()
        applied.clear()
        appliedLoaded = false
        held.clear()
        vaultNames = { null }
    }

    /** The account is going (sign-out, a server switch, a forbidding policy): the key, the queue and the list go. */
    fun dropAll() {
        runCatching { queue.clear() }
        runCatching { appliedStore.delete() }
        locked()
        publish(emptyList(), emptyList(), false)
    }

    // ---- the applied list, sealed to the account ----

    private fun loadApplied(live: VaultSession.Unlocked) {
        if (appliedLoaded) return
        appliedLoaded = true
        applied.clear()
        held.clear()
        val text = appliedStore.read()?.decodeToString() ?: return
        // Before the holds were kept, the file was the list of sealed records alone.
        val stored = runCatching { json.decodeFromString(Stored.serializer(), text) }.getOrNull()
            ?: runCatching { Stored(json.decodeFromString(ListSerializer(String.serializer()), text)) }.getOrNull() ?: return
        var unreadable = 0
        for (entry in stored.records.take(MAX_LISTED)) {
            // A record that is not this account's own (its MAC does not hold, round-9 review 2) is never read: one an
            // earlier version wrote among them. It is removed below, and counted (round-10 review 3).
            val plain = runCatching { live.account.openLocalRecord(APPLIED_RECORD, Bytes.fromB64(entry)) }.getOrNull()
            val record = plain?.let { p ->
                try {
                    runCatching { json.decodeFromString(AppliedRecord.serializer(), p.decodeToString()) }.getOrNull()
                } finally {
                    p.fill(0)
                }
            }
            if (record == null) {
                unreadable++
                continue
            }
            applied[record.id] = record
        }
        held += stored.held.take(MAX_LISTED)
        if (unreadable > 0) {
            storeApplied(live, Persist.VERIFIED) // the list as it can be read; an empty one removes the file
            dropped(unreadable)
        }
    }

    /**
     * Store the list and the holds, sealed to the account. Skipped for an operation whose session has ended (its maps were
     * emptied by the lock, not by anything that happened to the list). An empty list removes the file only when the
     * person emptied it ([Persist.PERSON]: Undo, Dismiss, Discard, deleting the login) or the vault showed every record
     * stale ([Persist.VERIFIED]); otherwise an empty map never overwrites what is stored.
     */
    private fun storeApplied(live: VaultSession.Unlocked, why: Persist) {
        if (!opAlive) return
        if (applied.isEmpty() && held.isEmpty()) {
            if (why != Persist.CHANGE) appliedStore.delete()
            return
        }
        val sealed = applied.values.toList().takeLast(MAX_LISTED).map { Bytes.toB64(live.account.sealLocalRecord(APPLIED_RECORD, json.encodeToString(AppliedRecord.serializer(), it).encodeToByteArray())) }
        appliedStore.write(json.encodeToString(Stored.serializer(), Stored(sealed, held.toList().takeLast(MAX_LISTED))).encodeToByteArray())
    }

    // ---- views ----

    private fun hostOf(site: String) = UriMatch.normalizeHostUnicode(site) ?: site

    private fun pendingViews(): List<PendingSaveView> = pending.map { (id, p) ->
        val via = if (p.login.source == "autofill") "Captured by the system's save prompt" else "Captured in Safari"
        val address = when (schemeOf(p.login.site)) {
            Scheme.UNKNOWN -> "for the domain only (no address)"
            Scheme.HTTP -> "on a page that was not encrypted"
            Scheme.HTTPS -> "on an https page"
        }
        PendingSaveView(id, hostOf(p.login.site), p.login.username, p.target?.doc?.name, schemeOf(p.login.site) == Scheme.HTTP, p.reason, "$via, $address.")
    }

    /** The vault each listed save's login is in now, by name (set whenever the list is published while unlocked). */
    private var vaultNames: (itemId: String) -> String? = { null }

    private fun appliedViews(): List<AppliedSaveView> = applied.values.filterNot { it.intent }.map {
        AppliedSaveView(it.id, hostOf(it.site), it.username, it.replacedName, schemeOf(it.site) == Scheme.HTTP, it.appliedAtMs, vaultNames(it.itemId))
    }

    companion object {
        /** What the list of automatic saves seals its records for ([Account.sealLocalRecord]). */
        const val APPLIED_RECORD = "applied-saves"

        const val MAX_AUTO_PER_RUN = 5
        const val HISTORY_MAX = 20
        const val MAX_LISTED = 200
        const val CLOCK_SKEW_MS = 2 * 60 * 1000L
        private val json = Json { ignoreUnknownKeys = true; encodeDefaults = true }

        const val PERSONAL_UNCONFIRMED = "Confirm your personal vault above first. This is saved once you have."
        const val PERSONAL_RECORD_MISSING = "The server's record of your personal vault is missing or unreadable right now, so nothing is saved by itself. Check this one and save it yourself, or wait until the record is back."
        const val SHARED_MATCH = "A login outside your personal vault already uses this username here. Save this one as your own, or discard it."
        const val SCHEME_UNKNOWN = "This was captured for the domain only, so andvari can't tell which of your logins it belongs to. Check it, then save or discard."
        const val OLDER_THAN_LOGIN = "This was captured before your login was last changed. Save it only if it is the newer password."
        const val FROM_THE_FUTURE = "This capture is dated in the future. Check it before saving."
        const val ALREADY_REPLACED = "A save listed above already updated this login's password. Check this one before saving."
        const val TOO_MANY = "Several logins were captured at once. Check the rest before saving them."
        const val NOT_A_SITE = "This was not captured on a web page andvari can save for."
        const val TARGET_CHANGED = "Your vault changed since this was captured. Check it again, then save."
        const val UNDO_CHANGED = "That login has changed since, so nothing was undone."
        const val UNDO_EDITED = "That login has been edited since it was saved, so it was not removed. Delete it yourself if you no longer want it."
    }
}
