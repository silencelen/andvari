package io.silencelen.andvari.core.app.content

import io.silencelen.andvari.core.app.BlobStore
import io.silencelen.andvari.core.app.FillSnapshotStore
import io.silencelen.andvari.core.app.InMemoryBlobs
import io.silencelen.andvari.core.app.InMemoryFillSnapshots
import io.silencelen.andvari.core.app.SaveQueueStore
import io.silencelen.andvari.core.client.items.CopyDeletion
import io.silencelen.andvari.core.client.items.ItemCacheNames
import io.silencelen.andvari.core.client.onboard.OpenedAccount
import io.silencelen.andvari.core.client.restore.BackupRestore
import io.silencelen.andvari.core.client.restore.RestoreRecords
import io.silencelen.andvari.core.crypto.CryptoProvider
import kotlinx.atomicfu.locks.SynchronizedObject
import kotlinx.atomicfu.locks.synchronized
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/**
 * The host's app-private storage for the content's kept records, by name (one file, or one directory of files, per
 * name). Names come from [ItemCacheNames.keptPrefix], so two accounts, or one account at two servers, never share one.
 */
interface KeptStorage {
    /** The one-record store [name] (made when first written). */
    fun record(name: String): FillSnapshotStore

    /** The set-aside files of [name] (made when first written). */
    fun blobs(name: String): BlobStore
}

/**
 * Where the content's kept records live for each account, and how long (spec 02 §8, the client policy's
 * `offlineCacheAllowed`). The app API holds one for the process and asks it for a [ContentKeeping] at every unlock:
 *
 * - **Allowed, with [disk]:** the records are files of [disk], under the account's own names.
 * - **Forbidden (or no [disk]):** whatever [disk] holds for the account is left untouched (only the policy's run, which
 *   counts it first, removes it: [keepingForWipe], [drop]), and this opening's records are kept in memory held HERE, so they outlive a lock (a save a lock cut short survives it) but never the process. Once an account's
 *   records are in memory they stay there until [drop], even if a later policy allows a cache: nothing kept under a
 *   forbidding policy is ever written to disk.
 * - **[drop]**, for one of the person's own acts only ([CopyDeletion]: sign-out, "Forget this server", account
 *   deletion, a policy that forbids an offline copy): every record of the account goes, on disk and in memory (the
 *   restore records only move into memory under such a policy), and the extensions' [queue] is emptied and their fill
 *   snapshot deleted. It needs no key, so it works locked. A lock does NOT drop, and neither does a
 *   session the server ended (design §4.4): its records, its queue and the files set aside stay for the read-only
 *   copy and for the next sign-in to the same account at the same origin, which sends what they hold.
 */
class ContentStores(
    private val crypto: CryptoProvider,
    private val disk: KeptStorage?,
    private val queue: SaveQueueStore = SaveQueueStore.None,
    /**
     * The App Group file the iPhone's AutoFill extension reads ([ContentFillSnapshot]); [FillSnapshotStore.None] on a
     * host with no such extension. Every [ContentKeeping] is given it; a policy that forbids keeping data on this device
     * deletes it at once, and [drop] deletes it whoever's it is (the App Group holds one account's at a time).
     */
    private val fillSnapshots: FillSnapshotStore = FillSnapshotStore.None,
) {
    private class Held {
        val moves = InMemoryFillSnapshots()
        val keptSaves = InMemoryFillSnapshots()
        val files = InMemoryBlobs()
        val applied = InMemoryFillSnapshots()
    }

    private val memory = HashMap<String, Held>()

    /**
     * The restore records each account keeps in this process's memory ([restoreRecords]): apart from [memory], so that
     * where they live never depends on where the content's own records live, and a restore never puts the content's
     * records in memory.
     */
    private val restoresHeld = HashMap<String, InMemoryFillSnapshots>()

    /** Held by every reading and writing of the restore records, and by [drop] and [carry]: a write never lands after them. */
    private val restoreLock = SynchronizedObject()

    /** Changes a lock overtook before they were kept, per account at one server: memory only, under every policy. */
    private val unsaved = HashMap<String, UnsavedAtLock>()

    /** The stores for [account] at [origin] under the policy as last read ([offlineCacheAllowed]; never read counts as false). */
    fun keeping(account: OpenedAccount, origin: String, offlineCacheAllowed: Boolean): ContentKeeping {
        val prefix = ItemCacheNames.keptPrefix(crypto, origin, account.userId)
        val held = memory[prefix]
        val lost = unsaved.getOrPut(prefix) { UnsavedAtLock() }
        if (!offlineCacheAllowed) runCatching { fillSnapshots.delete() }
        if (offlineCacheAllowed && disk != null && held == null) {
            return ContentKeeping(
                account, disk.record("$prefix$MOVES"), disk.record("$prefix$KEPT_SAVES"), disk.blobs("$prefix$FILES"),
                disk.record("$prefix$APPLIED"), queue, fillSnapshots, lost,
            )
        }
        // Nothing is removed before it is counted (decided on 2026-11-17): what [disk] holds for the account stays where
        // it is, unread by this opening, until the policy's own run counts and removes it ([drop]) or a policy that allows
        // a copy brings it back into use. This opening keeps its records in memory.
        val h = held ?: Held().also { memory[prefix] = it }
        return ContentKeeping(account, h.moves, h.keptSaves, h.files, h.applied, queue, fillSnapshots, lost)
    }

    /**
     * The records of the backup restores into [userId] at [origin] ([BackupRestore]), all in one kept record of the
     * account: a file of [disk] while the policy as last read allows an offline copy ([restoreRecordsAtRest]), this
     * process's memory otherwise. Unlike the content's records, the place does not depend on where the account's other
     * records are held: an account first opened before its policy was read keeps its content's records in memory for the
     * run, and its restore record is a file all the same (decided on 23 November 2026), so that a restore stopped
     * half-way goes on after the app was closed. They go with [drop] and move with [carry]. A name that is not a restore
     * record's ([BackupRestore.safeRecordName]) is refused before anything is read or written.
     */
    fun restoreRecords(origin: String, userId: String, offlineCacheAllowed: Boolean): RestoreRecords = restoreRecords(origin, userId) { offlineCacheAllowed }

    /**
     * As above, with the policy asked at every reading and writing ([offlineCacheAllowed], the policy as last read): the
     * place is never chosen once for a run, so a policy that forbids a copy arriving while a restore runs sends its next
     * write to memory, and the policy's own wipe ([drop]) is never followed by a write to the file.
     */
    fun restoreRecords(origin: String, userId: String, offlineCacheAllowed: () -> Boolean): RestoreRecords =
        KeptRestoreRecords(ItemCacheNames.keptPrefix(crypto, origin, userId), offlineCacheAllowed)

    /**
     * Every restore record of [userId] at [origin] this device holds, in memory and in the file (memory's copy where both
     * hold one), read without any key; null when one that is there cannot be read.
     */
    fun restoreRecordTexts(origin: String, userId: String): List<String>? = synchronized(restoreLock) {
        val prefix = ItemCacheNames.keptPrefix(crypto, origin, userId)
        runCatching {
            val onDisk = disk?.let { all(it.record("$prefix$RESTORES")) }.orEmpty()
            (onDisk + restoresHeld[prefix]?.let { all(it) }.orEmpty()).values.toList()
        }.getOrNull()
    }

    /**
     * Whether the restore records are a file of this device under a policy that [offlineCacheAllowed] or not: only with a
     * [disk], and only while the policy allows a copy. (The platform's own consent sits in [disk]: the desktop's records
     * are in memory while "Keep me signed in" is off.)
     */
    fun restoreRecordsAtRest(offlineCacheAllowed: Boolean): Boolean = offlineCacheAllowed && disk != null

    /**
     * Every restore record of one account, as one JSON object of name to record, replaced whole at each change: in the
     * file while [allowed] says the policy allows a copy, in [restoresHeld] otherwise. A record is read from memory first
     * and then from the file: a copy in memory is there only when no write to the file came after it, so it is the newer
     * one; the first write to the file afterwards takes it there and out of memory. Nothing is written to the file while
     * the policy forbids a copy, not even a removal.
     */
    /**
     * Every restore record of [store]. One that is there and cannot be read stops the caller (a record is never taken as
     * empty when it is unknown: a restore would mint new ids and store again what it stored before).
     */
    private fun all(store: FillSnapshotStore): Map<String, String> {
        val bytes = when (val r = store.readKept()) {
            is KeptRead.Read -> r.value ?: return emptyMap()
            KeptRead.Locked, KeptRead.Unreadable -> error("the restore's record cannot be read")
        }
        val o = runCatching { Json.parseToJsonElement(bytes.decodeToString()) as? JsonObject }.getOrNull() ?: error("the restore's record cannot be read")
        return o.mapNotNull { (k, v) -> (v as? JsonPrimitive)?.takeIf { it.isString }?.let { k to it.content } }.toMap()
    }

    private fun write(store: FillSnapshotStore, map: Map<String, String>) {
        check(store.write(JsonObject(map.mapValues { JsonPrimitive(it.value) }).toString().encodeToByteArray())) { "the restore's record was not written" }
    }

    private inner class KeptRestoreRecords(private val prefix: String, private val allowed: () -> Boolean) : RestoreRecords {
        private fun checked(name: String) = name.also { require(BackupRestore.safeRecordName(it)) { "not a restore record's name" } }

        private fun file(): FillSnapshotStore? = disk?.record("$prefix$RESTORES")

        /** The file, when the records' place is the file now. */
        private fun place(): FillSnapshotStore? = if (restoreRecordsAtRest(allowed())) file() else null

        private fun dropFrom(store: FillSnapshotStore, name: String) {
            val all = all(store)
            if (name in all) write(store, all - name)
        }

        override fun read(name: String): String? = synchronized(restoreLock) {
            val n = checked(name)
            restoresHeld[prefix]?.let { all(it)[n] } ?: file()?.let { all(it)[n] }
        }

        override fun replace(name: String, text: String): Unit = synchronized(restoreLock) {
            val n = checked(name)
            val file = place()
            if (file != null) {
                write(file, all(file) + (n to text))
                restoresHeld[prefix]?.let { dropFrom(it, n) }
            } else {
                val held = restoresHeld.getOrPut(prefix) { InMemoryFillSnapshots() }
                write(held, all(held) + (n to text))
            }
        }

        override fun remove(name: String): Unit = synchronized(restoreLock) {
            val n = checked(name)
            restoresHeld[prefix]?.let { dropFrom(it, n) }
            place()?.let { dropFrom(it, n) }
        }
    }

    /**
     * The stores for [account] at [origin] while the server's policy forbids the copy and its wipe is owed: the records as
     * they are (the platform's files, or what this process holds in memory), so that the policy's run counts and tries
     * what they hold before [drop] removes them. Nothing is removed here.
     */
    fun keepingForWipe(account: OpenedAccount, origin: String): ContentKeeping {
        val prefix = ItemCacheNames.keptPrefix(crypto, origin, account.userId)
        val held = memory[prefix]
        val lost = unsaved.getOrPut(prefix) { UnsavedAtLock() }
        if (disk != null && held == null) {
            return ContentKeeping(
                account, disk.record("$prefix$MOVES"), disk.record("$prefix$KEPT_SAVES"), disk.blobs("$prefix$FILES"),
                disk.record("$prefix$APPLIED"), queue, fillSnapshots, lost,
            )
        }
        val h = held ?: Held().also { memory[prefix] = it }
        return ContentKeeping(account, h.moves, h.keptSaves, h.files, h.applied, queue, fillSnapshots, lost)
    }

    /**
     * Every kept record of [userId] at [origin] goes, on disk and in memory, and the extensions' queue is emptied, for
     * [why] (the person's act; a session the server ended has no [CopyDeletion] and never calls this). For a policy that
     * forbids an offline copy the restore records are not deleted: they move into this process's memory.
     */
    @Suppress("UNUSED_PARAMETER")
    fun drop(origin: String, userId: String, why: CopyDeletion): Unit = synchronized(restoreLock) {
        val prefix = ItemCacheNames.keptPrefix(crypto, origin, userId)
        // A policy's removal makes the content again: the list of automatic saves the person was shown (an opening may
        // have saved a caught login by itself just before) is taken across it, in this process's memory only, as every
        // record kept under such a policy is; the next content reads it and keeps only what its new copy still holds.
        val shown = if (why != CopyDeletion.POLICY_FORBIDS_OFFLINE_COPY) null else {
            runCatching { (memory[prefix]?.applied ?: disk?.record("$prefix$APPLIED"))?.read() }.getOrNull()
        }
        // A policy's removal moves the account's restore records into this process's memory instead of deleting them
        // (decided on 23 November 2026): they hold no item and no readable key, and without them the same backup chosen
        // again would store a second time what a restore stopped half-way already stored. The copy in memory is the newer
        // one where both are there. A record that cannot be read goes with the copy, as before.
        val restores = if (why != CopyDeletion.POLICY_FORBIDS_OFFLINE_COPY) null else runCatching {
            val onDisk = disk?.let { all(it.record("$prefix$RESTORES")) }.orEmpty()
            onDisk + restoresHeld[prefix]?.let { all(it) }.orEmpty()
        }.getOrNull()?.takeIf { it.isNotEmpty() }
        unsaved.remove(prefix)?.clear()
        memory.remove(prefix)?.let { h ->
            h.moves.delete()
            h.keptSaves.delete()
            h.files.clear()
            h.applied.delete()
        }
        restoresHeld.remove(prefix)?.delete()
        disk?.let { deleteDisk(it, prefix) }
        // Logins the phone caught stay through a policy's wipe until the person answers them (decided on 2026-11-18):
        // the sealed entries and the public key they are sealed to are not part of the copy.
        if (why != CopyDeletion.POLICY_FORBIDS_OFFLINE_COPY) runCatching { queue.clear() }
        runCatching { fillSnapshots.delete() }
        if (shown != null) Held().also { memory[prefix] = it }.applied.write(shown)
        if (restores != null) write(InMemoryFillSnapshots().also { restoresHeld[prefix] = it }, restores)
    }

    /**
     * A followed move from [from] to [to] (design §4.4): the kept records of [userId] go with it, so a move, a save with
     * files or an automatic save a lock cut short is finished at the new address; nothing is deleted for the move. Held
     * in memory: re-filed under the new name. On disk: each record and file is copied to the new name, and the old one
     * removed only once its copy is written. A record that cannot be read, or a name already taken at [to], stops the
     * carry with everything still under the old names (unknown is never empty): false, and the host tries again later.
     *
     * The extensions' queue goes too ([QueueEntries.carry]): each capture of [userId] sealed at [from] just before the
     * move is filed again at [to], so the next unlock there offers it instead of dropping it as another origin's. A
     * queue that cannot be read, or an entry that cannot be written again, keeps what was not carried where it was, and
     * the answer is false. Call it with the content closed.
     */
    fun carry(from: String, to: String, userId: String): Boolean {
        val queued = QueueEntries.carry(queue, crypto, from, to, userId) == QueueEntries.Carried.DONE
        return synchronized(restoreLock) { carryRecords(from, to, userId) } && queued
    }

    private fun carryRecords(from: String, to: String, userId: String): Boolean {
        val old = ItemCacheNames.keptPrefix(crypto, from, userId)
        val new = ItemCacheNames.keptPrefix(crypto, to, userId)
        if (old == new) return true
        unsaved.remove(old)?.let { if (!unsaved.containsKey(new)) unsaved[new] = it }
        memory.remove(old)?.let { held ->
            if (memory.containsKey(new)) {
                memory[old] = held
                return false
            }
            memory[new] = held
        }
        restoresHeld.remove(old)?.let { held ->
            if (restoresHeld.containsKey(new)) {
                restoresHeld[old] = held
                return false
            }
            restoresHeld[new] = held
        }
        val disk = disk ?: return true
        for (suffix in listOf(MOVES, KEPT_SAVES, APPLIED, RESTORES)) if (!carryRecord(disk.record("$old$suffix"), disk.record("$new$suffix"))) return false
        return carryFiles(disk.blobs("$old$FILES"), disk.blobs("$new$FILES"))
    }

    private fun carryRecord(a: FillSnapshotStore, b: FillSnapshotStore): Boolean {
        val bytes = when (val r = a.readKept()) {
            is KeptRead.Read -> r.value ?: return true
            KeptRead.Locked, KeptRead.Unreadable -> return false
        }
        when (val there = b.readKept()) {
            is KeptRead.Read -> if (there.value != null) return false
            KeptRead.Locked, KeptRead.Unreadable -> return false
        }
        if (!runCatching { b.write(bytes) }.getOrDefault(false)) return false
        runCatching { a.delete() }
        return true
    }

    private fun carryFiles(a: BlobStore, b: BlobStore): Boolean {
        val ids = runCatching { a.idsStrict() }.getOrNull() ?: return false
        var all = true
        for (id in ids) {
            val bytes = runCatching { a.getStrict(id) }.getOrNull()
            val taken = runCatching { b.getStrict(id) != null }.getOrDefault(true)
            if (bytes == null || taken || !runCatching { b.put(id, bytes) }.getOrDefault(false)) {
                all = false
                continue
            }
            runCatching { a.delete(id) }
        }
        return all
    }

    /**
     * Whether a record of saves kept to be finished is there for [userId] at [origin], in this process's memory or on
     * disk: found without opening it (present or absent needs no key). A store that cannot say counts as there.
     */
    fun mayHoldKeptSaves(origin: String, userId: String): Boolean {
        val prefix = ItemCacheNames.keptPrefix(crypto, origin, userId)
        if (memory[prefix]?.keptSaves?.bytes != null) return true
        val d = disk ?: return false
        return runCatching { d.record("$prefix$KEPT_SAVES").read() != null }.getOrDefault(true)
    }

    /**
     * Whether this process holds in memory, for [userId] at [origin], saves kept to be finished or moves kept to be
     * finished (found without opening them): what ending the app would lose besides the queue.
     */
    fun holdsKeptInMemory(origin: String, userId: String): Boolean {
        val h = memory[ItemCacheNames.keptPrefix(crypto, origin, userId)] ?: return false
        return h.keptSaves.bytes != null || h.moves.bytes != null
    }

    /** True while the records of [userId] at [origin] are held in memory (tests, and a host's diagnostics). */
    fun inMemory(origin: String, userId: String): Boolean = ItemCacheNames.keptPrefix(crypto, origin, userId) in memory

    private fun deleteDisk(disk: KeptStorage, prefix: String) {
        runCatching { disk.record("$prefix$MOVES").delete() }
        runCatching { disk.record("$prefix$KEPT_SAVES").delete() }
        runCatching { disk.blobs("$prefix$FILES").clear() }
        runCatching { disk.record("$prefix$APPLIED").delete() }
        runCatching { disk.record("$prefix$RESTORES").delete() }
    }

    companion object {
        /** The suffixes of the four kept records' names, after [ItemCacheNames.keptPrefix]. */
        const val MOVES = "-moves"
        const val KEPT_SAVES = "-kept-saves"
        const val FILES = "-files"
        const val APPLIED = "-applied-saves"

        /** The suffix of the record of an account's backup restores ([restoreRecords]). */
        const val RESTORES = "-restores"
    }
}
