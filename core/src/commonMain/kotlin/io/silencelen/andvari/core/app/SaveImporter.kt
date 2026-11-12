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
 *    is newer than that login's last change, its scheme is known, and that login was not already replaced in this
 *    unlock; the password it replaces is kept in the login's history;
 *  - at most [MAX_AUTO_PER_RUN] entries are applied per unlock or return to the foreground;
 *  - every automatic save is listed, survives a lock (in app-private storage, sealed to the account), and can be
 *    undone one by one or all at once until the person dismisses the list.
 * Everything else stays listed with its reason, to be saved or discarded by hand.
 *
 * One mutex serializes a sync of the queue, an automatic apply, a manual save and an undo: they all read the vault,
 * decide, and write across suspension points.
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
) {
    val enabled: Boolean get() = queue !== SaveQueueStore.None

    private val mutex = Mutex()
    private val pending = LinkedHashMap<String, Pending>()
    private val applied = LinkedHashMap<String, AppliedRecord>()
    private var appliedLoaded = false

    /** Logins whose password an automatic save already replaced in this unlock: one replace per login per unlock. */
    private val replacedThisUnlock = HashSet<String>()

    /** How the vault took the last write: applied, or queued for the next sync. */
    private var lastOutcome = SaveOutcome.APPLIED

    private class Pending(val login: CapturedLogin, var target: VaultItem?, var reason: String? = null)

    /**
     * One automatic save, for the list and its undo. Kept sealed to the account (it names the password it wrote, so an
     * undo can tell whether the login changed since), in app-private storage.
     */
    @Serializable
    private data class AppliedRecord(
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
    )

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
    suspend fun sync(live: VaultSession.Unlocked, origin: String, allowed: Boolean, apply: Boolean, stillLive: () -> Boolean) = mutex.withLock {
        if (!enabled || !stillLive()) return@withLock
        if (!allowed) {
            dropAll()
            return@withLock
        }
        // The key the extensions seal to is this account's, whatever the file said: a published key that is not ours
        // (replaced by something else in the App Group, or left by another account) is put right here. What was
        // sealed to it in between cannot be read by this account, and could be read by whoever replaced it.
        val publication = SaveQueue.publication(origin, live.account)
        val published = queue.publication()
        if (published == null || !published.contentEquals(publication)) queue.publish(publication)
        loadApplied(live)

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
            val superseded = login.capturedAtMs < (newest[key(login)] ?: 0L) || applied.values.any { it.site == login.site && it.username == login.username && it.appliedAtMs >= login.capturedAtMs }
            val already = vault.any { sameLogin(it, login) && it.doc.login?.password == login.password }
            if (superseded || already) {
                queue.remove(id)
                continue
            }
            // An entry already listed keeps its reason; one that was mid-apply when this sync began is judged again.
            val was = before[id]
            pending[id] = Pending(login, personalTarget(vault, login, live.account), was?.reason)
        }
        if (apply) applyLocked(live, stillLive)
        if (stillLive()) publish(pendingViews(), appliedViews(), unreadable)
    }

    /** Why [p] is not saved by itself, or null when it may be. */
    private fun refusal(p: Pending, vault: List<VaultItem>, account: Account, now: Long, appliedThisRun: Int): String? {
        val captured = p.login
        val target = p.target
        return when {
            UriMatch.normalizeHost(captured.site) == null -> NOT_A_SITE
            captured.capturedAtMs > now + CLOCK_SKEW_MS -> FROM_THE_FUTURE
            target == null && vault.any { it.vaultId != account.personalVaultId && sameSite(it, captured) } -> SHARED_MATCH
            target == null && schemeOf(captured.site) == Scheme.UNKNOWN && vault.any { sameSite(it, captured) } -> SCHEME_UNKNOWN
            target == null && account.personalVaultId.isEmpty() -> HouseholdCopy.NO_PERSONAL_VAULT
            target != null && schemeOf(captured.site) == Scheme.UNKNOWN -> SCHEME_UNKNOWN
            target != null && target.itemId in replacedThisUnlock -> ALREADY_REPLACED
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
            if (p.reason != null) continue
            val record = try {
                write(live, id, p)
            } catch (c: CancellationException) {
                throw c
            } catch (t: Throwable) {
                p.reason = HouseholdCopy.forError(t)
                continue
            }
            if (!stillLive()) return
            queue.remove(id)
            pending.remove(id)
            applied[id] = record
            appliedThisRun++
            wroteAny = true
            if (record.replacedName != null) replacedThisUnlock += record.itemId
        }
        if (wroteAny) {
            storeApplied(live)
            wrote()
        }
    }

    /** Write one capture to the vault: the target's new password, or a new login under an id minted here. */
    private suspend fun write(live: VaultSession.Unlocked, id: String, p: Pending): AppliedRecord {
        val captured = p.login
        val host = UriMatch.normalizeHost(captured.site) ?: error("not a site")
        val now = clocks.wallMs()
        val target = p.target
        if (target == null) {
            val address = (if (schemeOf(captured.site) == Scheme.HTTP) "http://" else "https://") + host + (portOf(captured.site)?.let { ":$it" } ?: "")
            val doc = ItemDoc(type = "login", name = UriMatch.normalizeHostUnicode(captured.site) ?: host, login = LoginData(username = captured.username, password = captured.password, uris = listOf(address)))
            // The id is minted here, so the undo names exactly the login this save added.
            val itemId = Bytes.uuidV4FromBytes(crypto().randomBytes(16))
            lastOutcome = live.engine.saveWithUploads(null, doc, emptyList(), null, null, itemId)
            return AppliedRecord(id, captured.site, captured.username, itemId, null, captured.password, false, now)
        }
        val login = target.doc.login.orEmpty()
        val old = login.password.orEmpty()
        val keep = old.isNotEmpty() && old != captured.password
        // The history keeps each earlier password once, newest last, and no more than HISTORY_MAX of them.
        val history = if (keep) (login.passwordHistory.filter { it.password != old } + PasswordHistoryEntry(old, now)).takeLast(HISTORY_MAX) else login.passwordHistory
        lastOutcome = live.engine.save(target.itemId, target.doc.copy(login = login.copy(password = captured.password, passwordHistory = history)), target.vaultId)
        return AppliedRecord(id, captured.site, captured.username, target.itemId, target.doc.name, captured.password, keep, now)
    }

    // ---- by hand ----

    fun password(id: String): String? = pending[id]?.login?.password

    /**
     * Save one listed capture because the person said so: the new password of the personal-vault login the row named,
     * or a new login of their own. What the row showed is what is written: if the login it named changed or went, or
     * one appeared, nothing is written and the row is shown again as the vault is now.
     */
    suspend fun confirm(live: VaultSession.Unlocked, id: String, stillLive: () -> Boolean): ImportResult = mutex.withLock {
        val p = pending[id] ?: return@withLock ImportResult.Gone
        val vault = logins(live)
        val now = personalTarget(vault, p.login, live.account)
        if (now?.itemId != p.target?.itemId || now?.doc != p.target?.doc) {
            p.target = now
            p.reason = TARGET_CHANGED
            publish(pendingViews(), appliedViews(), false)
            return@withLock ImportResult.Failed(TARGET_CHANGED)
        }
        if (now == null && live.account.personalVaultId.isEmpty()) return@withLock ImportResult.Failed(HouseholdCopy.NO_PERSONAL_VAULT)
        if (UriMatch.normalizeHost(p.login.site) == null) return@withLock ImportResult.Failed(NOT_A_SITE)
        val record = write(live, id, p)
        if (!stillLive()) return@withLock ImportResult.Gone
        queue.remove(id)
        pending.remove(id)
        applied[id] = record
        storeApplied(live)
        wrote()
        publish(pendingViews(), appliedViews(), false)
        ImportResult.Done(queuedOffline = lastOutcome == SaveOutcome.QUEUED)
    }

    /** Discard one listed capture: it leaves the queue and nothing is written. */
    fun discard(id: String) {
        queue.remove(id)
        pending.remove(id)
        publish(pendingViews(), appliedViews(), false)
    }

    // ---- undo ----

    /**
     * Take back one save, exactly: a login it added is removed only if it is still as it was added, and a replaced
     * password is put back (and its history entry taken out again) only if the login still has the password this
     * save wrote and that history entry on top. Anything else has been changed since, and is left alone.
     */
    suspend fun undo(live: VaultSession.Unlocked, id: String, stillLive: () -> Boolean): ImportResult = mutex.withLock {
        val result = undoLocked(live, id)
        if (result is ImportResult.Done && stillLive()) {
            storeApplied(live)
            wrote()
            publish(pendingViews(), appliedViews(), false)
        }
        result
    }

    /** [undo] for every listed save; a failure names how many could not be undone. */
    suspend fun undoAll(live: VaultSession.Unlocked, stillLive: () -> Boolean): ImportResult = mutex.withLock {
        var failed = 0
        var queued = false
        for (id in applied.keys.toList()) {
            when (val r = undoLocked(live, id)) {
                is ImportResult.Done -> queued = queued || r.queuedOffline
                else -> failed++
            }
            if (!stillLive()) return@withLock ImportResult.Gone
        }
        storeApplied(live)
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
            live.engine.remove(record.itemId)
        } else {
            val top = login.passwordHistory.lastOrNull()
            if (record.keptOld && top?.retiredAt != record.appliedAtMs) return ImportResult.Failed(UNDO_CHANGED)
            val restored = if (record.keptOld) login.copy(password = top!!.password, passwordHistory = login.passwordHistory.dropLast(1)) else login.copy(password = null)
            live.engine.save(item.itemId, item.doc.copy(login = restored), item.vaultId)
        }
        applied.remove(id)
        replacedThisUnlock.remove(record.itemId)
        return ImportResult.Done(outcome == SaveOutcome.QUEUED)
    }

    /** The list has been read: it goes, in memory and in storage, and with it the undo from here. */
    fun dismiss() {
        applied.clear()
        appliedStore.delete()
        publish(pendingViews(), appliedViews(), false)
    }

    // ---- lifetime ----

    /** The vault locked: nothing opened stays in memory. The stored list is read again at the next unlock. */
    fun locked() {
        pending.clear()
        applied.clear()
        appliedLoaded = false
        replacedThisUnlock.clear()
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
        val sealed = appliedStore.read()?.let { runCatching { json.decodeFromString(ListSerializer(String.serializer()), it.decodeToString()) }.getOrNull() } ?: return
        for (entry in sealed.take(MAX_LISTED)) {
            val record = runCatching { json.decodeFromString(AppliedRecord.serializer(), live.account.openQueuedSave(Bytes.fromB64(entry)).decodeToString()) }.getOrNull() ?: continue
            applied[record.id] = record
        }
    }

    private fun storeApplied(live: VaultSession.Unlocked) {
        if (applied.isEmpty()) {
            appliedStore.delete()
            return
        }
        val sealed = applied.values.toList().takeLast(MAX_LISTED).map { Bytes.toB64(crypto().sealTo(live.account.identityPub, json.encodeToString(AppliedRecord.serializer(), it).encodeToByteArray())) }
        appliedStore.write(json.encodeToString(ListSerializer(String.serializer()), sealed).encodeToByteArray())
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

    private fun appliedViews(): List<AppliedSaveView> = applied.values.map {
        AppliedSaveView(it.id, hostOf(it.site), it.username, it.replacedName, schemeOf(it.site) == Scheme.HTTP, it.appliedAtMs)
    }

    companion object {
        const val MAX_AUTO_PER_RUN = 5
        const val HISTORY_MAX = 20
        const val MAX_LISTED = 200
        const val CLOCK_SKEW_MS = 2 * 60 * 1000L
        private val json = Json { ignoreUnknownKeys = true; encodeDefaults = true }

        const val SHARED_MATCH = "A login outside your personal vault already uses this username here. Save this one as your own, or discard it."
        const val SCHEME_UNKNOWN = "This was captured for the domain only, so andvari can't tell which of your logins it belongs to. Check it, then save or discard."
        const val OLDER_THAN_LOGIN = "This was captured before your login was last changed. Save it only if it is the newer password."
        const val FROM_THE_FUTURE = "This capture is dated in the future. Check it before saving."
        const val ALREADY_REPLACED = "This login's password was already updated a moment ago. Check this one before saving."
        const val TOO_MANY = "Several logins were captured at once. Check the rest before saving them."
        const val NOT_A_SITE = "This was not captured on a web page andvari can save for."
        const val TARGET_CHANGED = "Your vault changed since this was captured. Check it again, then save."
        const val UNDO_CHANGED = "That login has changed since, so nothing was undone."
    }
}
