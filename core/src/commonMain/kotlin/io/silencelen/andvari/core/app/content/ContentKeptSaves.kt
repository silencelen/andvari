package io.silencelen.andvari.core.app.content

import io.silencelen.andvari.core.app.BlobStore
import io.silencelen.andvari.core.app.FillSnapshotStore
import io.silencelen.andvari.core.app.InMemoryBlobs
import io.silencelen.andvari.core.client.ItemDoc
import io.silencelen.andvari.core.client.items.ItemFailure
import kotlinx.coroutines.CancellationException
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.json.Json

/**
 * A save with new files, kept until it is done (owner decision 2026-11-12): the item as it is to be saved, where it
 * goes, the revision it was edited from, and the id a new item was given. Its new files (each one's id and key are in
 * [ItemDoc.attachments]) lie beside it, each encrypted under its own key, so a save a lock cut short is finished after
 * the next unlock under the same ids and is never made twice. The old `PendingSave`, field for field.
 */
@Serializable
internal class KeptSave(
    val id: String,
    /** The item edited, or null for a new one. */
    val itemId: String?,
    /** The id a new item was given when its editor opened; an edit's own id otherwise. */
    val newItemId: String,
    /** The vault the item goes to: an edit's own, or the one a new item was put in. */
    val vaultId: String,
    /** The revision the edit was made from (0 for a new item). */
    val baseRev: Long,
    val doc: ItemDoc,
    /** The ids of the new files, which go up before the item that names them. */
    val newFiles: List<String>,
    /** The ids of the files the edit took off. */
    val removedFiles: List<String> = emptyList(),
    /**
     * Set once its files are on the server and the item's change was handed to the durable queue, which sends it later:
     * the revision the server held of the item then (0 for a new item). The record and its files stay until the server
     * holds the item at a newer revision with nothing of it left in the queue: until then the server may remove the
     * uploads no item names (it keeps them a day), and they are uploaded again before the waiting change is sent.
     */
    val queuedAt: Long? = null,
    /**
     * The server refused a queued change of this save's item for good while this save waited for its change to land, and
     * the save was not judged by that refusal yet (a change of its item still waited, or its editor was open). Kept here,
     * at rest with the record, so that a lock or a restart before the judging loses nothing; it holds the refusal's reason
     * only. Null in a record of a build before it, which reads as before.
     */
    val refusal: KeptRefusal? = null,
) {
    /** This save, its change handed to the durable queue when the server held the item at [rev]: a new change, no refusal. */
    fun queued(rev: Long) = KeptSave(id, itemId, newItemId, vaultId, baseRev, doc, newFiles, removedFiles, rev)

    /** This save, to be judged by [why]; null for a failure that is not a refusal for good. */
    fun refusedWith(why: ItemFailure): KeptSave? {
        val r = KeptRefusal.of(why) ?: return null
        return KeptSave(id, itemId, newItemId, vaultId, baseRev, doc, newFiles, removedFiles, queuedAt, r)
    }

    /** This save, judged by its refusal and not given up: the refusal goes. */
    fun judged() = KeptSave(id, itemId, newItemId, vaultId, baseRev, doc, newFiles, removedFiles, queuedAt)
}

/**
 * A refusal for good kept with a [KeptSave] until the save is judged by it: the server's reason and status for a row it
 * rejected, or no reason for a change it denied. Nothing else: no name, no content.
 */
@Serializable
internal class KeptRefusal(val reason: String? = null, val status: Int = 0) {
    fun failure(): ItemFailure = reason?.let { ItemFailure.Refused(it, status) } ?: ItemFailure.Denied(1)

    companion object {
        fun of(why: ItemFailure): KeptRefusal? = when (why) {
            is ItemFailure.Refused -> KeptRefusal(why.code, why.status)
            is ItemFailure.Denied -> KeptRefusal()
            else -> null
        }
    }
}

/**
 * The kept saves ([KeptSave]) and their files ([LocalRecords.KEPT_SAVES]). With a [log] and [records] they are sealed
 * to the account in the host's storage and survive a lock; without, they are kept in this object's memory only (the
 * fake, a host that gave no storage). A locked account is not an unreadable record: [load] answers null then, and
 * nothing is written or removed.
 */
internal class ContentKeptSaves(
    private val log: FillSnapshotStore?,
    private val blobs: BlobStore,
    private val records: LocalRecords?,
    /** Saves in records this version could not read, removed (round-10 review 3): how many, for the notice. */
    private val dropped: (Int) -> Unit,
) {
    private var memory: List<KeptSave> = emptyList()

    private fun decode(plain: ByteArray): List<KeptSave>? = runCatching { json.decodeFromString(serializer, plain.decodeToString()) }.getOrNull()

    /**
     * Every kept save: [KeptRead.Read] (empty when none is kept), [KeptRead.Locked] while the account is locked, and
     * [KeptRead.Unreadable] when the record is there but could not be read. Neither of the last two is
     * "nothing was kept": nothing is then written, forgotten or swept.
     */
    fun load(): KeptRead<List<KeptSave>> {
        val log = log ?: return KeptRead.Read(memory)
        val records = records ?: return KeptRead.Read(memory)
        val record = when (val r = log.readKept()) {
            is KeptRead.Read -> r.value ?: return KeptRead.Read(emptyList())
            KeptRead.Locked -> return KeptRead.Locked
            KeptRead.Unreadable -> return KeptRead.Unreadable
        }
        return when (val opened = records.open(LocalRecords.KEPT_SAVES, record)) {
            Unsealed.Locked -> KeptRead.Locked
            Unsealed.Failed -> KeptRead.Unreadable
            is Unsealed.Plain -> try {
                decode(opened.bytes)?.let { KeptRead.Read(it) } ?: removed()
            } finally {
                opened.bytes.fill(0)
            }
            Unsealed.NotOurs -> removed()
        }
    }

    /**
     * A record this version cannot read, or one without this account's MAC: nothing in it is used or even opened (a
     * sealed box to the identity key alone is one any contact can make, and under the clean break no earlier version's
     * record exists). It is removed, and said as one.
     */
    private fun removed(): KeptRead<List<KeptSave>> {
        runCatching { log!!.delete() }
        dropped(1)
        return KeptRead.Read(emptyList())
    }

    /** How keeping a save came out. */
    enum class Kept { KEPT, NOT_WRITTEN, UNREADABLE }

    /** Write [saves]; false when they could not be written (a full disk, or the account locked). */
    private fun write(saves: List<KeptSave>): Boolean {
        val log = log
        val records = records
        if (log == null || records == null) {
            memory = saves
            return true
        }
        if (saves.isEmpty()) {
            runCatching { log.delete() }
            return true
        }
        val plain = json.encodeToString(serializer, saves).encodeToByteArray()
        try {
            val sealed = records.seal(LocalRecords.KEPT_SAVES, plain) ?: return false
            return runCatching { log.write(sealed) }.getOrDefault(false)
        } finally {
            plain.fill(0)
        }
    }

    /** Keep [save], in place of the one with its id. Nothing is written unless what was kept could be read first. */
    fun keep(save: KeptSave): Kept = when (val all = load()) {
        is KeptRead.Read -> if (write(all.value.filter { it.id != save.id } + save)) Kept.KEPT else Kept.NOT_WRITTEN
        KeptRead.Locked -> Kept.NOT_WRITTEN
        KeptRead.Unreadable -> Kept.UNREADABLE
    }

    /**
     * [id] is done or given up: it goes, and the files only it named. Nothing changes while locked or unreadable.
     * True when no save [id] is kept now (it went, or there was none); false when it could not be told or removed.
     */
    fun forget(id: String): Boolean {
        val all = (load() as? KeptRead.Read)?.value ?: return false
        val gone = all.firstOrNull { it.id == id } ?: return true
        val rest = all.filter { it.id != id }
        if (!write(rest)) return false
        val stillNamed = rest.flatMapTo(HashSet()) { it.newFiles }
        gone.newFiles.filter { it !in stillNamed }.forEach(::dropBlob)
        return true
    }

    /** Set a file aside (encrypted) for a kept save. */
    fun putBlob(id: String, sealed: ByteArray): Boolean = runCatching { blobs.put(id, sealed) }.getOrDefault(false)

    /**
     * A copy of a file set aside: [KeptRead.Read] with null when it is not there, [KeptRead.Unreadable] when reading it
     * failed (then the save that names it is not given up: it waits for a read that works).
     */
    fun blob(id: String): KeptRead<ByteArray?> = try {
        KeptRead.Read(blobs.getStrict(id))
    } catch (c: CancellationException) {
        throw c
    } catch (e: Exception) {
        KeptRead.Unreadable
    }

    fun dropBlob(id: String) {
        runCatching { blobs.delete(id) }
    }

    /**
     * The files no kept save names and [inUse] does not hold (an editor the app was closed in left them): they go.
     * Only after the kept saves were read: while they are locked or unreadable, nothing is swept.
     */
    fun sweep(inUse: Set<String>) {
        val named = ((load() as? KeptRead.Read)?.value ?: return).flatMapTo(HashSet()) { it.newFiles }
        val ids = try {
            blobs.idsStrict()
        } catch (c: CancellationException) {
            throw c
        } catch (e: Exception) {
            return
        }
        ids.filter { it !in named && it !in inUse }.forEach(::dropBlob)
    }

    companion object {
        private val json = Json { ignoreUnknownKeys = true; encodeDefaults = true }
        private val serializer = ListSerializer(KeptSave.serializer())

        /** Kept in memory only, for a content with no host storage. */
        fun inMemory() = ContentKeptSaves(null, InMemoryBlobs(), null) {}
    }
}
