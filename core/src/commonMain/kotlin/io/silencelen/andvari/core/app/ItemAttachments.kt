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

    /** The longest a file's name is shown or saved as. */
    const val MAX_NAME_CHARS = 120

    /** What a file is called when its name leaves nothing to show. */
    const val FALLBACK_NAME = "File"

    /**
     * A file's name as every app shows it and offers it to a save dialog or Files (round-9 review 1, round-10 reviews 1
     * and 4; Android and the desktop app use it too). A name is whatever the person or client that added the file
     * wrote, a co-member's included, so it is never trusted as a path or as text that shows what it is: the last part
     * after any `/` or `\`, read by code point, without anything that does not show as itself ([hidden]: control,
     * format and bidirectional characters, so a right-to-left override cannot make a name that ends in "exe" read as one
     * that ends in "pdf"; surrogates, private-use and unassigned characters, line and paragraph separators, tags,
     * variation selectors, fillers and blanks), every run of spaces one space, no leading dots or spaces (no "..", no
     * hidden file) and no trailing ones, `:` made a hyphen, and at most [MAX_NAME_CHARS] code points with its extension
     * kept. A name that was only an extension keeps it after [FALLBACK_NAME] (".pdf" is "File.pdf"), and a name that
     * leaves nothing is [FALLBACK_NAME].
     */
    fun safeFileName(raw: String): String {
        val last = raw.substringAfterLast('/').substringAfterLast('\\')
        val points = ArrayList<Int>(last.length)
        var i = 0
        while (i < last.length) {
            val c = last[i]
            val cp = if (c.isHighSurrogate() && i + 1 < last.length && last[i + 1].isLowSurrogate()) {
                (0x10000 + ((c.code - 0xD800) shl 10) + (last[i + 1].code - 0xDC00)).also { i += 2 }
            } else {
                c.code.also { i += 1 }
            }
            when {
                hidden(cp) -> {}
                isSpace(cp) -> if (points.isNotEmpty() && points.last() != SPACE) points += SPACE
                cp == ':'.code -> points += '-'.code
                else -> points += cp
            }
        }
        var start = 0
        while (start < points.size && (points[start] == SPACE || points[start] == DOT)) start++
        var end = points.size
        while (end > start && (points[end - 1] == SPACE || points[end - 1] == DOT)) end--
        var name: List<Int> = points.subList(start, end)
        if (name.isEmpty()) return FALLBACK_NAME
        // Only an extension (".pdf"): it stays one, after the fallback name, rather than becoming the name ("pdf").
        if (points.subList(0, start).contains(DOT) && DOT !in name) name = codePoints("$FALLBACK_NAME.") + name
        if (name.size > MAX_NAME_CHARS) {
            val dot = name.lastIndexOf(DOT)
            val ext = if (dot > 0 && name.size - dot <= 16) name.subList(dot, name.size) else emptyList()
            var head = name.subList(0, MAX_NAME_CHARS - ext.size)
            while (head.isNotEmpty() && (head.last() == SPACE || head.last() == DOT)) head = head.subList(0, head.size - 1)
            name = head + ext
        }
        return buildString { for (cp in name) appendPoint(cp) }
    }

    private const val SPACE = 0x20
    private const val DOT = 0x2E

    /**
     * A code point that does not show as itself in a name: control (Cc), format (Cf, bidirectional controls among them),
     * surrogate (Cs), private-use (Co) and unassigned characters, line and paragraph separators (Zl, Zp), tags
     * (U+E0000 to U+E007F), variation selectors, the Hangul fillers, the blank Braille pattern, and the combining marks
     * that draw nothing. Outside the Basic Multilingual Plane, where the platform has no character table, the format and
     * private-use ranges are listed.
     */
    private fun hidden(cp: Int): Boolean = when {
        cp < 0x20 || cp in 0x7F..0x9F -> true
        cp in 0xD800..0xDFFF -> true
        cp in 0xE000..0xF8FF || cp >= 0xF0000 -> true
        cp == 0x2028 || cp == 0x2029 -> true
        cp in 0xE0000..0xE007F -> true
        cp in 0xFE00..0xFE0F || cp in 0xE0100..0xE01EF || cp in 0x180B..0x180F -> true
        cp == 0x115F || cp == 0x1160 || cp == 0x3164 || cp == 0xFFA0 -> true
        cp == 0x2800 -> true
        cp == 0x034F || cp == 0x17B4 || cp == 0x17B5 -> true
        cp == 0x110BD || cp == 0x110CD || cp in 0x13430..0x1343F || cp in 0x1BCA0..0x1BCA3 || cp in 0x1D173..0x1D17A -> true
        cp <= 0xFFFF -> cp.toChar().category.let { it == CharCategory.FORMAT || it == CharCategory.UNASSIGNED }
        else -> false
    }

    /** A space of any width (Zs): it becomes one plain space. */
    private fun isSpace(cp: Int): Boolean = cp == SPACE || (cp <= 0xFFFF && cp.toChar().category == CharCategory.SPACE_SEPARATOR)

    private fun codePoints(s: String): List<Int> = s.map { it.code }

    private fun StringBuilder.appendPoint(cp: Int) {
        if (cp < 0x10000) {
            append(cp.toChar())
        } else {
            append((0xD800 + ((cp - 0x10000) shr 10)).toChar())
            append((0xDC00 + ((cp - 0x10000) and 0x3FF)).toChar())
        }
    }

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

    fun filesOnly(name: String, removalsNotKept: Boolean = false) =
        "“$name” was changed after a save with files was cut short: the files it added were added to it as it is now, and nothing else of that save was kept" +
            (if (removalsNotKept) ": the files it took off are still in the item." else ".")

    /**
     * Round-10 review 3: what an earlier version of andvari kept on this device and this one could not carry over (its
     * records were not protected the way this version's are), counted, in one notice.
     */
    fun earlierRecords(count: Int) =
        (if (count == 1) "One thing an earlier version of andvari kept on this device" else "$count things an earlier version of andvari kept on this device") +
            " (a save with files that was cut short, a move that did not finish, or an entry in the list of automatic saves) could not be carried over to this version, so " +
            (if (count == 1) "it was" else "they were") + " removed. Check that your recent changes are there, and make again any that are missing."

    const val KEPT_IN_MEMORY =
        "This server no longer allows keeping data on this device, so a save with files that was cut short is kept only while andvari stays open."
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
    /** The ids of the files the edit took off: what it changed of the item's files besides [newFiles]. */
    val removedFiles: List<String> = emptyList(),
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
 * The kept saves ([PendingSave]) and their files. A kept save is sealed to the signed-in account with a MAC only it can
 * make ([Account.sealLocalRecord], round-9 review 2), so one written by anyone else is never read. It is kept on disk
 * ([disk], [diskBlobs]) when the origin's policy allows an offline cache ([durable], read when it is kept), and only in
 * memory otherwise, as the save queue is (design 2026-11-09, "Saving"). Both are read, so a save kept before the policy
 * changed is still found with its files ([leaveDisk] moves the disk's into memory when it forbids them, locked or not).
 * The lists are read and written only while unlocked, after [unlocked] has run; an empty list removes its log.
 */
internal class PendingSaves(private val disk: FillSnapshotStore, private val diskBlobs: BlobStore, private val durable: () -> Boolean) {
    private val json = Json { ignoreUnknownKeys = true; encodeDefaults = true }
    private val serializer = ListSerializer(PendingSave.serializer())
    private val memoryLog = InMemoryFillSnapshots()
    private val memoryBlobs = InMemoryBlobs()

    /** Sealed records taken off the disk while locked ([leaveDisk]): opaque until the next unlock opens them ([unlocked]). */
    private val held = ArrayList<ByteArray>()

    /** The saves [record] holds, when this account wrote it for kept saves; null otherwise. */
    private fun open(account: Account, record: ByteArray): List<PendingSave>? {
        val plain = runCatching { account.openLocalRecord(RECORD, record) }.getOrNull() ?: return null
        return try {
            runCatching { json.decodeFromString(serializer, plain.decodeToString()) }.getOrNull()
        } finally {
            plain.fill(0)
        }
    }

    private fun read(log: FillSnapshotStore, account: Account): List<PendingSave> {
        val record = log.read() ?: return emptyList()
        return open(account, record).orEmpty()
    }

    /**
     * How many saves a record this version cannot read held, to say so (round-10 review 3): one an earlier version wrote
     * (a sealed box without the MAC) is opened only to count them, and nothing in it is used; anything else counts as one.
     */
    private fun countUnreadable(account: Account, record: ByteArray): Int {
        val plain = runCatching { account.openQueuedSave(record) }.getOrNull() ?: return 1
        return try {
            runCatching { json.decodeFromString(serializer, plain.decodeToString()).size }.getOrNull()?.coerceAtLeast(1) ?: 1
        } finally {
            plain.fill(0)
        }
    }

    /** What an unlock found ([unlocked]): saves moved into memory while locked, and saves in records that could not be read. */
    class Found(val movedToMemory: Int, val unreadable: Int)

    /**
     * At an unlock, before anything reads the kept saves: the records taken off the disk while locked (a policy that
     * forbids keeping data, round-10 review 2) are opened and join the ones in memory, and a record on disk this version
     * cannot read (an earlier version's, round-10 review 3) is removed. Both are counted, for the notices that say so:
     * nothing kept goes unsaid.
     */
    fun unlocked(account: Account): Found {
        var moved = 0
        var unreadable = 0
        val records = held.toList()
        held.clear()
        for (record in records) {
            val saves = open(account, record)
            if (saves == null) {
                unreadable += countUnreadable(account, record)
            } else if (saves.isNotEmpty()) {
                val kept = read(memoryLog, account).filter { m -> saves.none { it.id == m.id } }
                if (write(memoryLog, account, kept + saves)) moved += saves.size else unreadable += saves.size
            }
            record.fill(0)
        }
        val onDisk = runCatching { disk.read() }.getOrNull()
        if (onDisk != null && open(account, onDisk) == null) {
            unreadable += countUnreadable(account, onDisk)
            runCatching { disk.delete() }
        }
        return Found(moved, unreadable)
    }

    private fun write(log: FillSnapshotStore, account: Account, saves: List<PendingSave>): Boolean {
        if (saves.isEmpty()) {
            log.delete()
            return true
        }
        val plain = json.encodeToString(serializer, saves).encodeToByteArray()
        try {
            return log.write(account.sealLocalRecord(RECORD, plain))
        } finally {
            plain.fill(0)
        }
    }

    /** Every kept save, on disk and in memory. */
    fun load(account: Account): List<PendingSave> = read(disk, account) + read(memoryLog, account)

    /** Keep [save], in place of the one with its id, where the policy says now: false when it could not be written. */
    fun keep(account: Account, save: PendingSave): Boolean {
        val (here, there) = if (durable()) disk to memoryLog else memoryLog to disk
        val others = read(there, account)
        if (others.any { it.id == save.id }) write(there, account, others.filter { it.id != save.id })
        return write(here, account, read(here, account).filter { it.id != save.id } + save)
    }

    /** [id] is done or given up: it goes, and the files only it named. */
    fun forget(account: Account, id: String) {
        var gone: PendingSave? = null
        for (log in listOf(disk, memoryLog)) {
            val all = read(log, account)
            val hit = all.firstOrNull { it.id == id } ?: continue
            gone = hit
            write(log, account, all.filter { it.id != id })
        }
        val stillNamed = load(account).flatMapTo(HashSet()) { it.newFiles }
        gone?.newFiles?.filter { it !in stillNamed }?.forEach(::dropBlob)
    }

    /** Set a file aside where the policy says now. */
    fun putBlob(id: String, sealed: ByteArray): Boolean = (if (durable()) diskBlobs else memoryBlobs).put(id, sealed)

    /** A file set aside, wherever it was set aside. */
    fun blob(id: String): ByteArray? = memoryBlobs.get(id) ?: diskBlobs.get(id)

    fun dropBlob(id: String) {
        memoryBlobs.delete(id)
        diskBlobs.delete(id)
    }

    /** The files no kept save names and [inUse] does not hold (an editor the app was closed in left them): they go. */
    fun sweep(account: Account, inUse: Set<String>) {
        if (held.isNotEmpty()) return // their files are named by records not opened yet ([unlocked] first)
        val named = load(account).flatMapTo(HashSet()) { it.newFiles }
        for (store in listOf(memoryBlobs, diskBlobs)) store.ids().filter { it !in named && it !in inUse }.forEach { store.delete(it) }
    }

    /**
     * The policy no longer allows keeping data on this device (round-9 review 8): what is kept on disk goes, moved into
     * memory first, so the saves are still finished while the app runs. Unlocked, the saves of [account] are moved with
     * their files, and how many is returned for the notice that says so. Locked ([account] null, a policy probe at
     * launch or on return, round-10 review 2), nothing can be opened and nothing is deleted unseen: the sealed record
     * and every file, encrypted as they are, move into memory as opaque bytes, and the next unlock opens them and says
     * so ([unlocked]).
     */
    fun leaveDisk(account: Account?): Int {
        var moved = 0
        if (account != null) {
            val onDisk = runCatching { read(disk, account) }.getOrDefault(emptyList())
            if (onDisk.isNotEmpty()) {
                for (id in onDisk.flatMap { it.newFiles }) {
                    diskBlobs.get(id)?.let { bytes ->
                        memoryBlobs.put(id, bytes)
                        bytes.fill(0)
                    }
                }
                val kept = read(memoryLog, account).filter { m -> onDisk.none { it.id == m.id } }
                if (write(memoryLog, account, kept + onDisk)) moved = onDisk.size
            }
        } else {
            runCatching { disk.read() }.getOrNull()?.let { held += it }
            for (id in runCatching { diskBlobs.ids() }.getOrDefault(emptyList())) {
                runCatching { diskBlobs.get(id) }.getOrNull()?.let { bytes ->
                    memoryBlobs.put(id, bytes)
                    bytes.fill(0)
                }
            }
        }
        runCatching { disk.delete() }
        runCatching { diskBlobs.clear() }
        return moved
    }

    /** The account is going: every kept save and file goes, on disk and in memory. */
    fun dropAll() {
        runCatching { disk.delete() }
        runCatching { diskBlobs.clear() }
        memoryLog.delete()
        memoryBlobs.clear()
        held.forEach { it.fill(0) }
        held.clear()
    }

    companion object {
        /** What kept saves are sealed for ([Account.sealLocalRecord]). */
        const val RECORD = "kept-saves"
    }
}
