package io.silencelen.andvari.core.app.content

import io.silencelen.andvari.core.app.AppliedSaveView
import io.silencelen.andvari.core.app.CapturedLogin
import io.silencelen.andvari.core.app.FillSnapshotStore
import io.silencelen.andvari.core.app.PendingSaveView
import io.silencelen.andvari.core.app.SaveKeyPublication
import io.silencelen.andvari.core.app.SaveQueue
import io.silencelen.andvari.core.app.SaveQueueStore
import io.silencelen.andvari.core.client.ItemDoc
import io.silencelen.andvari.core.client.LoginData
import io.silencelen.andvari.core.client.OriginCanon
import io.silencelen.andvari.core.client.PasswordHistoryEntry
import io.silencelen.andvari.core.client.VaultItem
import io.silencelen.andvari.core.client.autofill.UriMatch
import io.silencelen.andvari.core.client.items.ItemResult
import io.silencelen.andvari.core.client.items.SavedItem
import io.silencelen.andvari.core.client.items.Written
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.CryptoProvider
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.json.Json

/** How a save or an undo the person asked for ended. */
internal sealed interface SaveOutcome {
    /** Written; [written] says whether it reached the server or is kept on this device for a later sync ([Written.waits]). */
    class Done(val written: Written) : SaveOutcome

    /** There was nothing to do it to (already gone, or the account locked). */
    object Gone : SaveOutcome

    class Failed(val message: String) : SaveOutcome
}

/**
 * The content's side of the extensions' save queue (design 2026-11-09, "Saving"): the old `SaveImporter`, over the
 * item engine and the new account type, with its rules unchanged:
 *  - a NEW login is added to the PERSONAL vault, and a new password replaces an existing one only in the personal
 *    vault (never a shared vault), for the login with the same host, port, scheme and username, only when the capture
 *    is newer than that login's last change, its scheme is known, and no earlier automatic replace of it is listed;
 *  - the personal vault must be writable here: accepted, verified, neither frozen, failed nor withheld (a save is never
 *    put in a vault left out of the AutoFill working set), and the server not stopped;
 *  - at most [MAX_AUTO_PER_RUN] entries are applied per read, and one the cap held back waits for the person for good;
 *  - every automatic save is listed, survives a lock (sealed to the account, [LocalRecords.APPLIED_SAVES]) and can be
 *    undone until dismissed. Everything else stays listed with its reason, to be saved or discarded by hand.
 *
 * A locked account is not an unreadable entry: once the account's keys are wiped, nothing is opened, removed or stored
 * (the operation stops where it is; an intent stored before a write is settled at the next unlock).
 *
 * One mutex serializes a read of the queue, an automatic apply, a manual save, an undo, a discard and a dismissal.
 */
internal class ContentSaves(
    private val queue: SaveQueueStore,
    private val appliedStore: FillSnapshotStore,
    private val records: LocalRecords,
    private val source: ContentSource,
    private val crypto: CryptoProvider,
    private val wallMs: () -> Long,
    /** The controller's own write path: a save into a named vault ([newItemId] for a new item). */
    private val write: suspend (itemId: String?, doc: ItemDoc, vaultId: String, newItemId: String?) -> ItemResult<SavedItem>,
    private val remove: suspend (itemId: String) -> ItemResult<Written>,
    /** Whether the personal vault takes a write now (the working set's rule). */
    private val personalWritable: () -> Boolean,
    private val vaultName: (String) -> String?,
    /** The content is still open. */
    private val alive: () -> Boolean,
    /** Entries of the list an earlier version wrote, which this one cannot read, were removed: how many. */
    private val dropped: (Int) -> Unit,
) {
    private val mutex = Mutex()

    /** The account locked in the middle of an operation: it stops, and nothing more of it is stored or removed. */
    private class LockedNow : Exception("the account locked")

    /**
     * The queue or the stored list could not be read: the operation stops, nothing is stored, removed or
     * applied, and the next operation reads again. Unknown is never empty.
     */
    private class UnreadableNow : Exception("a kept record could not be read")

    private suspend fun <T> op(gone: T, unreadable: T, block: suspend () -> T): T = mutex.withLock {
        if (!alive()) return@withLock gone
        try {
            block()
        } catch (e: LockedNow) {
            gone
        } catch (e: UnreadableNow) {
            unreadable
        }
    }

    private val unreadableOutcome = SaveOutcome.Failed(ContentCopy.SAVES_LIST_UNREADABLE)

    /** What reading the queue came to. */
    enum class QueueRead {
        /** Read; nothing had to be removed unread. */
        READ,

        /** Read; entries this account cannot open were removed ([SAVES_UNREADABLE]). */
        ENTRIES_REMOVED,

        /** The queue or the stored list could not be read: nothing was applied, stored or removed. */
        UNREADABLE,

        /** The account locked or the content closed: nothing was done. */
        NOT_DONE,
    }

    private enum class Persist { CHANGE, PERSON, VERIFIED }

    private class Pending(val login: CapturedLogin, var target: VaultItem?, var reason: String? = null)

    private val pending = LinkedHashMap<String, Pending>()
    private val applied = LinkedHashMap<String, AppliedRecord>()
    private var appliedLoaded = false
    private val held = LinkedHashSet<String>()

    /**
     * Intents (by record id) whose write the server took while the read after it got no answer, so the login is not in
     * the list yet. Each stays stored and its entry is not written again until a sync has been answered ([pulled]).
     */
    private val sentUnseen = HashSet<String>()

    /** A sync was answered: what it did not bring was not taken, and the next read judges it as before. */
    fun pulled() = sentUnseen.clear()

    private fun waitsToShow(queueId: String) = applied.values.any { it.intent && it.entry == queueId && it.id in sentUnseen }

    /** The old `SaveImporter.AppliedRecord`, field for field, so a list the old app kept opens here. */
    @Serializable
    private class AppliedRecord(
        val id: String,
        val site: String,
        val username: String,
        val itemId: String,
        val replacedName: String?,
        val password: String,
        val keptOld: Boolean,
        val appliedAtMs: Long,
        val intent: Boolean = false,
        val capturedAtMs: Long = 0,
        val docDigest: String? = null,
        val queueId: String = "",
    ) {
        val entry: String get() = queueId.ifEmpty { id }
        fun settled() = AppliedRecord(id, site, username, itemId, replacedName, password, keptOld, appliedAtMs, false, capturedAtMs, docDigest, queueId)
    }

    @Serializable
    private class Stored(val records: List<String> = emptyList(), val held: List<String> = emptyList())

    /** What the content lists now. */
    fun pendingViews(): List<PendingSaveView> = pending.map { (id, p) ->
        val via = if (p.login.source == "autofill") "Captured by the system's save prompt" else "Captured in Safari"
        val address = when (schemeOf(p.login.site)) {
            Scheme.UNKNOWN -> "for the domain only (no address)"
            Scheme.HTTP -> "on a page that was not encrypted"
            Scheme.HTTPS -> "on an https page"
            Scheme.APP -> "in an app"
        }
        PendingSaveView(id, hostOf(p.login.site), p.login.username, p.target?.doc?.name, schemeOf(p.login.site) == Scheme.HTTP, p.reason, "$via, $address.")
    }

    fun appliedViews(): List<AppliedSaveView> = applied.values.filterNot { it.intent }.map {
        AppliedSaveView(it.id, hostOf(it.site), it.username, it.replacedName, schemeOf(it.site) == Scheme.HTTP, it.appliedAtMs, source.item(it.itemId)?.let { item -> vaultName(item.vaultId) })
    }

    // ---- what a capture is ----

    /** [APP]: captured in an Android app (`androidapp://<package>`, [ContentCapture.appSite]); never read as a web address. */
    private enum class Scheme { HTTP, HTTPS, UNKNOWN, APP }

    private fun schemeOf(site: String): Scheme {
        val s = site.trim()
        return when {
            ContentCapture.isApp(s) -> Scheme.APP
            s.startsWith("http://", ignoreCase = true) -> Scheme.HTTP
            s.startsWith("https://", ignoreCase = true) -> Scheme.HTTPS
            else -> Scheme.UNKNOWN
        }
    }

    private fun savedScheme(uri: String) = if (schemeOf(uri) == Scheme.HTTP) Scheme.HTTP else Scheme.HTTPS

    private fun portOf(address: String): String? {
        val authority = address.trim().substringAfter("://").takeWhile { it != '/' && it != '?' && it != '#' }.substringAfterLast('@')
        val port = if (authority.startsWith("[")) authority.substringAfter("]", "").removePrefix(":") else authority.substringAfter(':', "")
        return port.takeIf { it.isNotEmpty() && it.all(Char::isDigit) && it != "443" && it != "80" }
    }

    /**
     * Where a capture may be saved: an app it names by a valid package, or a web host. An app address is never read as
     * a web host (a package such as `com.bank.app` is also a DNS name, and a login for the app must not fill that site).
     */
    private fun addressable(site: String): Boolean =
        if (ContentCapture.isApp(site)) ContentCapture.appPackage(site) != null else UriMatch.normalizeHost(site) != null

    private fun sameSite(item: VaultItem, captured: CapturedLogin): Boolean {
        val login = item.doc.login ?: return false
        if (login.username.orEmpty() != captured.username) return false
        if (ContentCapture.isApp(captured.site)) {
            val pkg = ContentCapture.appPackage(captured.site) ?: return false
            return login.uris.any { ContentCapture.appPackage(it) == pkg }
        }
        val host = UriMatch.normalizeHost(captured.site) ?: return false
        return login.uris.any { !ContentCapture.isApp(it) && UriMatch.normalizeHost(it) == host && portOf(it) == portOf(captured.site) }
    }

    private fun sameLogin(item: VaultItem, captured: CapturedLogin): Boolean {
        val scheme = schemeOf(captured.site)
        if (scheme == Scheme.APP) return sameSite(item, captured)
        val host = UriMatch.normalizeHost(captured.site) ?: return false
        return sameSite(item, captured) && (item.doc.login ?: LoginData()).uris.any {
            !ContentCapture.isApp(it) && UriMatch.normalizeHost(it) == host && portOf(it) == portOf(captured.site) && (scheme == Scheme.UNKNOWN || savedScheme(it) == scheme)
        }
    }

    private fun key(c: CapturedLogin) = "${UriMatch.normalizeHost(c.site)}|${portOf(c.site)}|${schemeOf(c.site)}|${c.username}"

    private fun personalTarget(logins: List<VaultItem>, captured: CapturedLogin): VaultItem? {
        val personal = source.personalVaultId ?: return null
        return logins.firstOrNull { it.vaultId == personal && sameLogin(it, captured) }
    }

    private fun logins() = source.items().filter { it.doc.type == "login" }

    private fun hostOf(site: String) =
        if (ContentCapture.isApp(site)) ContentCapture.appPackage(site) ?: site else UriMatch.normalizeHostUnicode(site) ?: site

    private fun digest(doc: ItemDoc): String = Bytes.toB64(crypto.sha256(json.encodeToString(ItemDoc.serializer(), doc).encodeToByteArray()))

    private fun replaceListed(itemId: String) = applied.values.any { !it.intent && it.replacedName != null && it.itemId == itemId }

    // ---- the queue ----

    /** The key the extensions seal to, as the old app published it, byte for byte. */
    private fun publication(origin: String): ByteArray =
        json.encodeToString(SaveKeyPublication.serializer(), SaveKeyPublication(origin = OriginCanon.canonicalOrigin(origin), userId = records.userId, identityPub = Bytes.toB64(records.identityPub())))
            .encodeToByteArray()

    /**
     * One entry as this account at [origin]: the capture, or null for anything that is not a save sealed to this account
     * here (oversized, malformed, another account's, a seal that does not open, an inside naming another account, a
     * capture older than [SaveQueue.MAX_AGE_MS]). A locked account throws [LockedNow]: the entry is never judged then.
     */
    private fun open(origin: String, bytes: ByteArray, now: Long): CapturedLogin? {
        val here = OriginCanon.canonicalOrigin(origin)
        val entry = QueueEntries.decode(bytes) ?: return null
        if (entry.userId != records.userId || entry.origin != here) return null
        // An entry a followed move carried here: its inside names the address it was captured at, and only that one.
        val inside = entry.carriedFrom ?: here
        val sealed = runCatching { Bytes.fromB64(entry.sealed) }.getOrNull() ?: return null
        val plain = when (val o = records.openQueued(sealed)) {
            Unsealed.Locked -> throw LockedNow()
            Unsealed.Failed -> throw UnreadableNow()
            Unsealed.NotOurs -> return null
            is Unsealed.Plain -> o.bytes
        }
        val login = try {
            runCatching { json.decodeFromString(CapturedLogin.serializer(), plain.decodeToString()) }.getOrNull()
        } finally {
            plain.fill(0)
        }
        return login?.takeIf {
            it.magic == SaveQueue.MAGIC && it.userId == records.userId && it.origin == inside && it.password.isNotEmpty() &&
                now - it.capturedAtMs < SaveQueue.MAX_AGE_MS &&
                it.password.length <= SaveQueue.MAX_FIELD_CHARS && it.username.length <= SaveQueue.MAX_FIELD_CHARS && it.site.isNotBlank() && it.site.length <= SaveQueue.MAX_SITE_CHARS
        }
    }

    /** How many entries the last read removed because this account could not open them ([QueueRead.ENTRIES_REMOVED]). */
    var removedUnread = 0
        private set

    /**
     * Publish the key, read the queue and (with [apply]) save what may be saved by itself. With [allowed] false (the
     * policy forbids keeping data on this device) no key is published and the queue and the list are emptied.
     * A queue or a list that cannot be read changes nothing ([QueueRead.UNREADABLE]): what is listed stays as it was.
     */
    suspend fun sync(origin: String, allowed: Boolean, apply: Boolean): QueueRead = op(QueueRead.NOT_DONE, QueueRead.UNREADABLE) {
        if (!allowed) {
            dropAll()
            return@op QueueRead.READ
        }
        val publication = publication(origin)
        val published = runCatching { queue.publication() }.getOrNull()
        if (published == null || !published.contentEquals(publication)) runCatching { queue.publish(publication) }
        loadApplied()
        val entries = try {
            queue.entriesStrict()
        } catch (c: CancellationException) {
            throw c
        } catch (e: Exception) {
            throw UnreadableNow()
        }
        settle()
        val now = wallMs()
        val vault = logins()
        var unreadable = false
        removedUnread = 0
        val opened = ArrayList<Pair<String, CapturedLogin>>()
        for ((id, bytes) in entries) {
            val login = open(origin, bytes, now)
            if (login == null) {
                // Said and counted ([removedUnread]), never dropped without a word.
                unreadable = true
                removedUnread++
                runCatching { queue.remove(id) }
            } else {
                opened += id to login
            }
        }
        opened.sortBy { it.second.capturedAtMs }
        val newest = HashMap<String, Long>()
        for ((_, login) in opened) newest[key(login)] = login.capturedAtMs
        val before = HashMap(pending)
        pending.clear()
        for ((id, login) in opened) {
            val superseded = login.capturedAtMs < (newest[key(login)] ?: 0L) ||
                applied.values.any { !it.intent && it.site == login.site && it.username == login.username && (if (it.capturedAtMs > 0) it.capturedAtMs else it.appliedAtMs) >= login.capturedAtMs }
            val already = vault.any { sameLogin(it, login) && it.doc.login?.password == login.password }
            if (superseded || already) {
                runCatching { queue.remove(id) }
                continue
            }
            val was = before[id]
            val waitedForVault = was?.reason == ContentCopy.NO_PERSONAL_VAULT || was?.reason == PERSONAL_NOT_WRITABLE
            val reason = if (id in held) TOO_MANY else was?.reason?.takeUnless { waitedForVault && personalWritable() }
            pending[id] = Pending(login, personalTarget(vault, login), reason)
        }
        if (held.retainAll(pending.keys)) storeApplied(Persist.VERIFIED)
        if (apply) applyAll()
        if (unreadable) QueueRead.ENTRIES_REMOVED else QueueRead.READ
    }

    /** Why [p] is not saved by itself, or null when it may be. */
    private fun refusal(p: Pending, vault: List<VaultItem>, now: Long, appliedThisRun: Int): String? {
        val captured = p.login
        val target = p.target
        val personal = source.personalVaultId
        return when {
            !addressable(captured.site) -> NOT_A_SITE
            target == null && personal == null -> ContentCopy.NO_PERSONAL_VAULT
            // Never a vault left out of the working set: frozen, failed, withheld, not accepted, or a stopped server.
            !personalWritable() -> PERSONAL_NOT_WRITABLE
            captured.capturedAtMs > now + CLOCK_SKEW_MS -> FROM_THE_FUTURE
            target == null && vault.any { it.vaultId != personal && sameSite(it, captured) } -> SHARED_MATCH
            target == null && schemeOf(captured.site) == Scheme.UNKNOWN && vault.any { sameSite(it, captured) } -> SCHEME_UNKNOWN
            target != null && schemeOf(captured.site) == Scheme.UNKNOWN -> SCHEME_UNKNOWN
            target != null && replaceListed(target.itemId) -> ALREADY_REPLACED
            target != null && captured.capturedAtMs <= target.updatedAt -> OLDER_THAN_LOGIN
            appliedThisRun >= MAX_AUTO_PER_RUN -> TOO_MANY
            else -> null
        }
    }

    private suspend fun applyAll() {
        var appliedThisRun = 0
        for ((id, p) in pending.toList()) {
            if (!alive()) return
            if (p.reason != null || waitsToShow(id)) continue
            val vault = logins()
            p.target = personalTarget(vault, p.login)
            p.reason = refusal(p, vault, wallMs(), appliedThisRun)
            if (p.reason == TOO_MANY && held.add(id)) storeApplied(Persist.CHANGE)
            if (p.reason != null) continue
            when (val r = writeCapture(id, p)) {
                null -> appliedThisRun++
                is ItemResult.Failed -> p.reason = ContentCopy.forFailure(r.why, ContentCopy.During.SAVE)
                is ItemResult.Ok -> {
                    if (!alive()) return
                    finish(id, r.value.first)
                    appliedThisRun++
                }
            }
        }
    }

    private fun finish(queueId: String, record: AppliedRecord) {
        if (!alive()) return
        runCatching { queue.remove(queueId) }
        pending.remove(queueId)
        held.remove(queueId)
        applied[record.id] = record.settled()
        storeApplied(Persist.CHANGE)
    }

    /** Bring the stored list in line with the vault (the old `settleLocked`): an intent whose write shows is listed. */
    private fun settle() {
        var changed = false
        for ((id, record) in applied.toList()) {
            val item = source.item(record.itemId)
            when {
                record.intent && item == null && id in sentUnseen -> Unit
                record.intent && item != null && (record.replacedName == null || item.doc.login?.password == record.password) -> {
                    runCatching { queue.remove(record.entry) }
                    applied[id] = record.settled()
                    changed = true
                }
                record.intent || item == null -> {
                    applied.remove(id)
                    changed = true
                }
            }
        }
        if (changed) storeApplied(Persist.VERIFIED)
    }

    /**
     * Write one capture through the controller's write path: the personal target's new password, or a new login in the
     * personal vault under an id minted here. The record is stored as an intent first; a write that fails takes it back.
     */
    private suspend fun writeCapture(queueId: String, p: Pending): ItemResult<Pair<AppliedRecord, Written>>? {
        val captured = p.login
        val app = ContentCapture.appPackage(captured.site)
        val host = (if (ContentCapture.isApp(captured.site)) app else UriMatch.normalizeHost(captured.site))
            ?: return ItemResult.Failed(io.silencelen.andvari.core.client.items.ItemFailure.NotAllowed(io.silencelen.andvari.core.client.items.ItemRefusal.ITEM_GONE))
        val personal = source.personalVaultId ?: return ItemResult.Failed(io.silencelen.andvari.core.client.items.ItemFailure.NotAllowed(io.silencelen.andvari.core.client.items.ItemRefusal.NO_PERSONAL_VAULT))
        val now = wallMs()
        val target = p.target
        val old = target?.doc?.login?.password.orEmpty()
        val keep = target != null && old.isNotEmpty() && old != captured.password
        val itemId = target?.itemId ?: ContentController.freshId(crypto)
        val address = if (app != null) {
            UriMatch.ANDROID_APP_SCHEME + app
        } else {
            (if (schemeOf(captured.site) == Scheme.HTTP) "http://" else "https://") + host + (portOf(captured.site)?.let { ":$it" } ?: "")
        }
        val name = if (app != null) app else UriMatch.normalizeHostUnicode(captured.site) ?: host
        val doc = ItemDoc(type = "login", name = name, login = LoginData(username = captured.username, password = captured.password, uris = listOf(address)))
        val record = AppliedRecord(
            ContentController.freshId(crypto), captured.site, captured.username, itemId, target?.doc?.name, captured.password, keep, now,
            intent = true, capturedAtMs = captured.capturedAtMs, docDigest = if (target == null) digest(doc) else null, queueId = queueId,
        )
        applied[record.id] = record
        try {
            storeApplied(Persist.CHANGE)
        } catch (e: LockedNow) {
            applied.remove(record.id)
            throw e
        }
        val r = try {
            if (target == null) {
                write(null, doc, personal, itemId)
            } else {
                val login = target.doc.login ?: LoginData()
                val history = if (keep) (login.passwordHistory.filter { it.password != old } + PasswordHistoryEntry(old, now)).takeLast(HISTORY_MAX) else login.passwordHistory
                write(target.itemId, target.doc.copy(login = login.copy(password = captured.password, passwordHistory = history)), target.vaultId, null)
            }
        } catch (c: CancellationException) {
            throw c // the intent stays stored: the next unlock settles it
        }
        return when (r) {
            is ItemResult.Ok -> if (target == null && source.item(itemId) == null) {
                // Never listed as saved on the save's word alone: the login must be in the list. Not in it after an
                // answered write means the read after the write got no answer: the server has it, so it is never said as
                // gone nor written again; the intent stays and a later read settles it ([sentUnseen]).
                sentUnseen += record.id
                null
            } else {
                ItemResult.Ok(record to r.value.outcome)
            }
            is ItemResult.Failed -> {
                applied.remove(record.id)
                runCatching { storeApplied(Persist.CHANGE) }
                r
            }
        }
    }

    // ---- by hand ----

    fun password(id: String): String? = pending[id]?.login?.password

    /** Save one listed capture because the person said so: what its row showed, or nothing. */
    suspend fun confirm(id: String): SaveOutcome = op(SaveOutcome.Gone, unreadableOutcome) {
        val p = pending[id] ?: return@op SaveOutcome.Gone
        // Taken by the server already, and not in the list yet: nothing is written again.
        if (waitsToShow(id)) return@op SaveOutcome.Done(Written.APPLIED)
        // The stored list first: an intent stored over a list never read would replace it.
        loadApplied()
        val now = personalTarget(logins(), p.login)
        if (now?.itemId != p.target?.itemId || now?.doc != p.target?.doc) {
            p.target = now
            p.reason = TARGET_CHANGED
            return@op SaveOutcome.Failed(TARGET_CHANGED)
        }
        if (now == null && source.personalVaultId == null) return@op SaveOutcome.Failed(ContentCopy.NO_PERSONAL_VAULT)
        // By hand too, never a vault left out of the working set.
        if (!personalWritable()) return@op SaveOutcome.Failed(PERSONAL_NOT_WRITABLE)
        if (!addressable(p.login.site)) return@op SaveOutcome.Failed(NOT_A_SITE)
        when (val r = writeCapture(id, p)) {
            null -> SaveOutcome.Done(Written.APPLIED)
            is ItemResult.Failed -> SaveOutcome.Failed(ContentCopy.forFailure(r.why, ContentCopy.During.SAVE))
            is ItemResult.Ok -> {
                if (!alive()) return@op SaveOutcome.Gone
                finish(id, r.value.first)
                SaveOutcome.Done(r.value.second)
            }
        }
    }

    /** Discard one listed capture: it leaves the queue and nothing is written. */
    suspend fun discard(id: String): SaveOutcome = op(SaveOutcome.Gone, unreadableOutcome) {
        loadApplied()
        runCatching { queue.remove(id) }
        pending.remove(id)
        if (held.remove(id)) storeApplied(Persist.PERSON)
        SaveOutcome.Done(Written.APPLIED)
    }

    // ---- undo ----

    suspend fun undo(id: String): SaveOutcome = op(SaveOutcome.Gone, unreadableOutcome) {
        loadApplied()
        val r = undoOne(id)
        if (r is SaveOutcome.Done) storeApplied(Persist.PERSON)
        r
    }

    suspend fun undoAll(): SaveOutcome = op(SaveOutcome.Gone, unreadableOutcome) {
        loadApplied()
        var failed = 0
        // The first undo kept on this device says how they wait.
        var written = Written.APPLIED
        for (id in applied.keys.toList()) {
            when (val r = undoOne(id)) {
                is SaveOutcome.Done -> if (!written.waits) written = r.written
                else -> failed++
            }
            if (!alive()) return@op SaveOutcome.Gone
        }
        storeApplied(Persist.PERSON)
        if (failed == 0) SaveOutcome.Done(written) else SaveOutcome.Failed(if (failed == 1) UNDO_CHANGED else "$failed of these have changed since, so they were not undone.")
    }

    private suspend fun undoOne(id: String): SaveOutcome {
        val record = applied[id] ?: return SaveOutcome.Gone
        val item = source.item(record.itemId)
        val login = item?.doc?.login
        if (item == null || login == null || login.password.orEmpty() != record.password || login.username.orEmpty() != record.username) return SaveOutcome.Failed(UNDO_CHANGED)
        val r: ItemResult<Written> = if (record.replacedName == null) {
            if (record.docDigest != null && digest(item.doc) != record.docDigest) return SaveOutcome.Failed(UNDO_EDITED)
            remove(record.itemId)
        } else {
            val top = login.passwordHistory.lastOrNull()
            if (record.keptOld && top?.retiredAt != record.appliedAtMs) return SaveOutcome.Failed(UNDO_CHANGED)
            val restored = if (record.keptOld) login.copy(password = top!!.password, passwordHistory = login.passwordHistory.dropLast(1)) else login.copy(password = null)
            when (val s = write(item.itemId, item.doc.copy(login = restored), item.vaultId, null)) {
                is ItemResult.Ok -> ItemResult.Ok(s.value.outcome)
                is ItemResult.Failed -> s
            }
        }
        return when (r) {
            is ItemResult.Ok -> {
                applied.remove(id)
                SaveOutcome.Done(r.value)
            }
            is ItemResult.Failed -> SaveOutcome.Failed(ContentCopy.forFailure(r.why, ContentCopy.During.SAVE))
        }
    }

    /** The person deleted [itemId] in this app: a save that added it has nothing left to undo. */
    suspend fun itemDeleted(itemId: String) = op(Unit, Unit) {
        loadApplied()
        val ids = applied.filterValues { it.itemId == itemId }.keys
        if (ids.isEmpty()) return@op
        ids.forEach(applied::remove)
        storeApplied(Persist.PERSON)
    }

    /** The list has been read: it goes, in memory and in storage, and with it the undo. Never a list that was not read. */
    suspend fun dismiss(): SaveOutcome = op(SaveOutcome.Gone, unreadableOutcome) {
        loadApplied()
        applied.clear()
        storeApplied(Persist.PERSON)
        SaveOutcome.Done(Written.APPLIED)
    }

    /** The policy forbids keeping data here: the key, the queue and the list go. */
    private fun dropAll() {
        runCatching { queue.clear() }
        runCatching { appliedStore.delete() }
        pending.clear()
        applied.clear()
        held.clear()
    }

    // ---- the applied list, sealed to the account ----

    private fun loadApplied() {
        if (appliedLoaded) return
        // A list that cannot be read is unknown, never empty: stored over, it would be lost.
        val text = when (val r = appliedStore.readKept()) {
            is KeptRead.Read -> r.value?.decodeToString()
            KeptRead.Locked -> throw LockedNow()
            KeptRead.Unreadable -> throw UnreadableNow()
        }
        val stored = text?.let {
            runCatching { json.decodeFromString(Stored.serializer(), it) }.getOrNull()
                ?: runCatching { Stored(json.decodeFromString(ListSerializer(String.serializer()), it)) }.getOrNull()
        }
        val read = LinkedHashMap<String, AppliedRecord>()
        // A file that is not a list at all is removed and said, as every record this version cannot read.
        var unreadable = if (text != null && stored == null) 1 else 0
        for (entry in stored?.records.orEmpty().take(MAX_LISTED)) {
            val sealed = runCatching { Bytes.fromB64(entry) }.getOrNull()
            val record = when (val o = sealed?.let { records.open(LocalRecords.APPLIED_SAVES, it) }) {
                Unsealed.Locked -> throw LockedNow() // nothing is judged, nothing is rewritten
                Unsealed.Failed -> throw UnreadableNow()
                is Unsealed.Plain -> try {
                    runCatching { json.decodeFromString(AppliedRecord.serializer(), o.bytes.decodeToString()) }.getOrNull()
                } finally {
                    o.bytes.fill(0)
                }
                Unsealed.NotOurs, null -> null
            }
            if (record == null) unreadable++ else read[record.id] = record
        }
        applied.clear()
        applied.putAll(read)
        held.clear()
        held += stored?.held.orEmpty().take(MAX_LISTED)
        appliedLoaded = true
        if (unreadable > 0) {
            storeApplied(Persist.VERIFIED)
            dropped(unreadable)
        }
    }

    /** Store the list and the holds, sealed; an empty one removes the file only when the person or the vault emptied it. */
    private fun storeApplied(why: Persist) {
        if (!alive()) return
        if (applied.isEmpty() && held.isEmpty()) {
            if (why != Persist.CHANGE) runCatching { appliedStore.delete() }
            return
        }
        val sealed = applied.values.toList().takeLast(MAX_LISTED).map {
            val plain = json.encodeToString(AppliedRecord.serializer(), it).encodeToByteArray()
            try {
                Bytes.toB64(records.seal(LocalRecords.APPLIED_SAVES, plain) ?: throw LockedNow())
            } finally {
                plain.fill(0)
            }
        }
        runCatching { appliedStore.write(json.encodeToString(Stored.serializer(), Stored(sealed, held.toList().takeLast(MAX_LISTED))).encodeToByteArray()) }
    }

    companion object {
        const val MAX_AUTO_PER_RUN = 5
        const val HISTORY_MAX = 20
        const val MAX_LISTED = 200
        const val CLOCK_SKEW_MS = 2 * 60 * 1000L
        private val json = Json { ignoreUnknownKeys = true; encodeDefaults = true }

        /** NEW: the personal vault is frozen, failed or withheld here, or the server is stopped. */
        const val PERSONAL_NOT_WRITABLE = "Your personal vault can't be written on this device right now, so nothing is saved by itself. Check this one and save it later."
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
        /** Caught logins this account could not open were removed (a marked placeholder); how many is not known. */
        val SAVES_UNREADABLE: String get() = ContentCopy.capturesUnreadable(0)

        /** [SAVES_UNREADABLE] with the number of entries removed ([removedUnread]); the general line where it is not known. */
        fun savesUnreadable(n: Int): String = ContentCopy.capturesUnreadable(n)
    }
}
