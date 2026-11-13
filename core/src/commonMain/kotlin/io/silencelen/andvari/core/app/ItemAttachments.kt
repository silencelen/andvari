package io.silencelen.andvari.core.app

import io.silencelen.andvari.core.client.Account
import io.silencelen.andvari.core.client.AttachmentRef
import io.silencelen.andvari.core.client.ItemDoc
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.json.Json

/** One file of an item, as its detail and its editor list it. */
data class AttachmentView(val id: String, val name: String, val size: Long)

/**
 * How large one file, and an item's files together, may be: the server's policy (spec 02 §6), held within what this app
 * reads into memory ([AttachmentRules]). A file is checked against these before it is read.
 */
data class AttachmentLimitsView(val perFileBytes: Long, val perItemBytes: Long)

/** The files of the item an editor has open: the ones it keeps, the ones it adds, and what they come to. */
data class AttachmentDraftView(
    val kept: List<AttachmentView>,
    val added: List<AttachmentView>,
    val totalBytes: Long,
    val limits: AttachmentLimitsView,
)

/** A save with new files running: how many of its files went up, of how many. */
data class UploadView(val done: Int, val total: Int)

/** What reading one file of an item gave: its bytes (in memory only), or why there are none. */
class AttachmentContent(val name: String, val bytes: ByteArray?, val error: String?)

/** The rules for files (owner decision 2026-11-12, spec 02 §6). */
object AttachmentRules {
    /** The server's default limits, when no policy has been read. */
    const val DEFAULT_FILE_BYTES = 25L * 1024 * 1024
    const val DEFAULT_ITEM_BYTES = 100L * 1024 * 1024

    /**
     * The most this app reads into memory for one file, whatever a server allows. A file is held whole while it is
     * encrypted or decrypted, and the steps copy it a few times: about six times its size at the peak, 300 MB for a
     * file of this size, which every phone iOS 17 runs on holds in the foreground.
     */
    const val MAX_FILE_BYTES = 50L * 1024 * 1024

    /** The most one item's files may come to here. Each file is encrypted and set aside when it is added, one at a time. */
    const val MAX_ITEM_BYTES = 200L * 1024 * 1024

    /**
     * How long a lock on leaving the app waits for running work, an upload most of all: the screen is covered at once,
     * and the vault locks when the work ends or this runs out (the iOS background-task window).
     */
    const val BACKGROUND_GRACE_MS = 30_000L

    /** The policy's limits, held to this app's: a server can lower them, never raise them past what the app holds. */
    fun limits(policyFileBytes: Long?, policyItemBytes: Long?): AttachmentLimitsView =
        AttachmentLimitsView(
            perFileBytes = (policyFileBytes ?: DEFAULT_FILE_BYTES).coerceIn(1, MAX_FILE_BYTES),
            perItemBytes = (policyItemBytes ?: DEFAULT_ITEM_BYTES).coerceIn(1, MAX_ITEM_BYTES),
        )

    /** What a limit is called in a sentence: "25 MB", or "500 KB" below a megabyte. */
    fun size(bytes: Long): String =
        if (bytes >= 1024 * 1024) "${(bytes + 512 * 1024) / (1024 * 1024)} MB" else "${maxOf(1, (bytes + 512) / 1024)} KB"

    /** Why a file of [size] bytes cannot join files that come to [held] bytes, or null when it can. */
    fun refusal(size: Long, held: Long, limits: AttachmentLimitsView): String? = when {
        size <= 0 -> "This file is empty."
        size > limits.perFileBytes -> "This file is larger than ${size(limits.perFileBytes)}, the most one file can be here."
        held + size > limits.perItemBytes -> "This item's files would come to more than ${size(limits.perItemBytes)}, the most one item can hold."
        else -> null
    }
}

/** What the app says about files. */
internal object AttachmentCopy {
    const val FILE_NOT_SET_ASIDE = "This file could not be set aside for the save. Try again."
    const val FILE_GONE = "This file is no longer in the item."
    val FILE_TOO_LARGE_TO_OPEN =
        "This file is larger than ${AttachmentRules.size(AttachmentRules.MAX_FILE_BYTES)}, more than this app opens. Open it in andvari on a computer."
    const val KEPT_SAVE_DONE = "A save with files that was cut short is done."
    const val KEPT_SAVES_DONE = "saves with files that were cut short are done."

    fun savedWithoutFiles(name: String, why: String) = "“$name” could not be saved with its files: $why"

    fun savedLater(name: String) = "“$name” has not been saved with its files yet. andvari tries again the next time you unlock."
}

/**
 * A save with new files, kept until it is done (owner decision 2026-11-12): the item as it is to be saved, where it
 * goes, the revision it was edited from, and the id a new item was given. Its new files (each one's id and key are in
 * [ItemDoc.attachments]) lie beside it, each encrypted under its own key ([BlobStore]), so a save a lock cut short is
 * finished after the next unlock under the same ids and is never made twice. Sealed to the account with the keys
 * inside; nothing in it or beside it is ever a decrypted file.
 */
@Serializable
internal data class PendingSave(
    val id: String,
    /** The item edited, or null for a new one. */
    val itemId: String?,
    /** The id a new item was given when its editor opened; an edit's own id otherwise. */
    val newItemId: String,
    /** The vault the item goes to: an edit's own, or the one a new item was put in. */
    val vaultId: String,
    /** The revision the edit was made from (0 for a new item): someone else's change since is kept as a conflict copy. */
    val baseRev: Long,
    val doc: ItemDoc,
    /** The ids of the new files, which go up before the item that names them. */
    val newFiles: List<String>,
)

/** Where files set aside for a save lie, encrypted, by attachment id: the app's own storage on iOS, memory in tests. */
interface BlobStore {
    fun put(id: String, bytes: ByteArray): Boolean

    fun get(id: String): ByteArray?

    fun delete(id: String)

    /** The ids of every file set aside. */
    fun ids(): List<String>

    /** Every file set aside goes (the account is going). */
    fun clear()
}

/** [BlobStore] in memory (tests, and hosts that keep nothing across a restart). */
class InMemoryBlobs : BlobStore {
    private val map = LinkedHashMap<String, ByteArray>()

    override fun put(id: String, bytes: ByteArray): Boolean {
        map[id] = bytes.copyOf()
        return true
    }

    override fun get(id: String): ByteArray? = map[id]?.copyOf()

    override fun delete(id: String) {
        map.remove(id)?.fill(0)
    }

    override fun ids(): List<String> = map.keys.toList()

    override fun clear() {
        map.values.forEach { it.fill(0) }
        map.clear()
    }
}

/**
 * The kept saves ([PendingSave]), sealed to the signed-in account, and their files. They are on disk ([disk],
 * [diskBlobs]) while [durable] says the origin's policy allows an offline cache, and only in memory otherwise, as the
 * save queue is (design 2026-11-09, "Saving"). The list is read and written only while unlocked; an empty list removes
 * the log.
 */
internal class PendingSaves(private val disk: FillSnapshotStore, private val diskBlobs: BlobStore, private val durable: () -> Boolean) {
    private val json = Json { ignoreUnknownKeys = true; encodeDefaults = true }
    private val serializer = ListSerializer(PendingSave.serializer())
    private val memoryLog = InMemoryFillSnapshots()
    private val memoryBlobs = InMemoryBlobs()

    private val log: FillSnapshotStore get() = if (durable()) disk else memoryLog
    private val blobs: BlobStore get() = if (durable()) diskBlobs else memoryBlobs

    fun load(account: Account): List<PendingSave> {
        val sealed = log.read() ?: return emptyList()
        val plain = runCatching { account.openQueuedSave(sealed) }.getOrNull() ?: return emptyList()
        return try {
            runCatching { json.decodeFromString(serializer, plain.decodeToString()) }.getOrDefault(emptyList())
        } finally {
            plain.fill(0)
        }
    }

    private fun store(account: Account, saves: List<PendingSave>): Boolean {
        if (saves.isEmpty()) {
            log.delete()
            return true
        }
        val plain = json.encodeToString(serializer, saves).encodeToByteArray()
        try {
            return log.write(account.cryptoProvider().sealTo(account.identityPub, plain))
        } finally {
            plain.fill(0)
        }
    }

    /** Keep [save], in place of the one with its id: false when it could not be written. */
    fun keep(account: Account, save: PendingSave): Boolean = store(account, load(account).filter { it.id != save.id } + save)

    /** [id] is done or given up: it goes, and the files only it named. */
    fun forget(account: Account, id: String) {
        val all = load(account)
        val gone = all.firstOrNull { it.id == id } ?: return
        val rest = all.filter { it.id != id }
        store(account, rest)
        val stillNamed = rest.flatMapTo(HashSet()) { it.newFiles }
        gone.newFiles.filter { it !in stillNamed }.forEach { blobs.delete(it) }
    }

    fun putBlob(id: String, sealed: ByteArray): Boolean = blobs.put(id, sealed)

    fun blob(id: String): ByteArray? = blobs.get(id)

    fun dropBlob(id: String) = blobs.delete(id)

    /** The files no kept save names and [inUse] does not hold (an editor the app was closed in left them): they go. */
    fun sweep(account: Account, inUse: Set<String>) {
        val named = load(account).flatMapTo(HashSet()) { it.newFiles }
        blobs.ids().filter { it !in named && it !in inUse }.forEach { blobs.delete(it) }
    }

    /** What is kept on disk goes (the policy no longer allows it there, or the account is going). */
    fun dropDurable() {
        runCatching { disk.delete() }
        runCatching { diskBlobs.clear() }
    }

    /** The account is going: every kept save and file goes, on disk and in memory. */
    fun dropAll() {
        dropDurable()
        memoryLog.delete()
        memoryBlobs.clear()
    }
}
