package io.silencelen.andvari.desktop.trust

import io.silencelen.andvari.core.app.BlobStore
import io.silencelen.andvari.core.app.FillSnapshotStore
import io.silencelen.andvari.core.app.InMemoryBlobs
import io.silencelen.andvari.core.app.InMemoryFillSnapshots
import io.silencelen.andvari.core.app.content.ContentStores
import io.silencelen.andvari.core.app.content.KeptStorage
import io.silencelen.andvari.core.app.content.StrictBlobStore
import io.silencelen.andvari.core.app.content.StrictRecordStore
import io.silencelen.andvari.core.crypto.CryptoProvider
import io.silencelen.andvari.core.crypto.createCryptoProvider
import java.io.File

/**
 * Where the vault's content keeps what a lock cuts short (an unfinished move or copy, a save with new files, the saves
 * applied from the queue): [AppEngine.contentStores][io.silencelen.andvari.core.app.engine.AppEngine.contentStores],
 * which the app interface asks every platform to pass: the content's own [ContentStores], made once for the
 * process over [storage]. Every record is sealed to its account by core, under its account's own names; core uses the
 * files only while the server's policy allows data at rest, and deletes them only by the person's own act (sign-out,
 * a forgotten server, account deletion, a policy that forbids an offline copy), never because the server ended a
 * session.
 *
 * The desktop's own rule sits on top (as for the sign-in and the vault cache): the records are files
 * in [dir] only while the person keeps the sign-in on this computer, and in memory for the run otherwise. Turning the
 * opt-in on moves what memory holds to disk; turning it off moves what disk holds to memory and deletes the files, so
 * a kept save survives the switch either way. Files found without the opt-in (a crash between the switch and the
 * delete) are deleted unread when the stores are made. No extension saves on desktop, so there is no save queue.
 */
class DesktopContentStores(
    private val dir: File,
    crypto: CryptoProvider = createCryptoProvider(),
    /**
     * Whether the files found now are deleted unread: by default when [keepOnDisk] is off. [DesktopHome] passes it
     * from the switch's three states, so a switch that could not be read deletes nothing.
     */
    wipeAtStart: Boolean? = null,
    /** The app's own directory: no delete here reaches outside it or follows a link ([SafeDelete], note N1). */
    private val within: File = dir.absoluteFile.parentFile,
    private val keepOnDisk: () -> Boolean,
) {
    private val records = HashMap<String, OptInRecord>()
    private val blobSets = HashMap<String, OptInBlobs>()

    init {
        if (wipeAtStart ?: !keepOnDisk()) SafeDelete.tree(dir, within)
    }

    /** The kept records by the names core gives ([io.silencelen.andvari.core.client.items.ItemCacheNames.keptPrefix] and a suffix). */
    val storage: KeptStorage = object : KeptStorage {
        override fun record(name: String): FillSnapshotStore = synchronized(records) {
            records.getOrPut(name) { OptInRecord(File(dir, safe(name)), keepOnDisk) }
        }

        override fun blobs(name: String): BlobStore = synchronized(records) {
            blobSets.getOrPut(name) { OptInBlobs(File(dir, safe(name)), within, keepOnDisk) }
        }
    }

    val stores: ContentStores = ContentStores(crypto, storage)

    /**
     * The opt-in is about to go off: every record and file on disk is copied to memory, and nothing is deleted yet,
     * so a reader between the switch and [keepChanged] finds what was kept.
     */
    fun carryToMemory() {
        synchronized(records) {
            records.values.forEach { it.copyToMemory() }
            blobSets.values.forEach { it.copyToMemory() }
        }
    }

    /** The opt-in changed: every record follows it. */
    fun keepChanged(on: Boolean) {
        synchronized(records) {
            records.values.forEach { it.keepChanged(on) }
            blobSets.values.forEach { it.keepChanged(on) }
        }
        if (!on) SafeDelete.tree(dir, within)
    }

    private companion object {
        val NAME = Regex("^[A-Za-z0-9._-]{1,128}$")

        /** Core's names are hex and dashes; anything else never names a file here. */
        fun safe(name: String): String {
            require(NAME.matches(name) && name != "." && name != "..") { "not a kept record's name" }
            return name
        }
    }
}

/**
 * One record in an owner-only file, replaced by an atomic rename so a reader sees the old one or the new one.
 *
 * Two readers, as core's stores have them: [readOrThrow] ([StrictRecordStore], what core reads where an answer of
 * "nothing there" would delete or replace something) is null only when there is no file and throws an
 * [java.io.IOException] when the file is there and cannot be read, because a record that cannot be read is unknown,
 * never empty. The plain [read] keeps [FillSnapshotStore]'s old promise never to throw: a read error is logged and
 * answers null.
 */
internal class FileRecord(private val file: File) : FillSnapshotStore, StrictRecordStore {
    override fun write(bytes: ByteArray): Boolean = runCatching { writeOwnerOnly(file, bytes) }.getOrDefault(false)

    override fun readOrThrow(): ByteArray? = if (!SafeDelete.exists(file)) null else readOrThrow(file)

    override fun read(): ByteArray? = neverThrows("a kept record could not be read") { readOrThrow() }

    override fun delete() {
        file.delete()
        sweepTemps(file)
    }
}

/**
 * Files set aside for a save, one owner-only file per attachment id; only an id this app mints names a file here. The
 * strict readers ([StrictBlobStore]) tell "not there" from "could not be read"; the plain [get] and [ids] keep
 * [BlobStore]'s promise never to throw (a read error is logged and answers null or an empty list).
 */
internal class FileBlobs(private val dir: File, private val within: File = dir.absoluteFile.parentFile) : BlobStore, StrictBlobStore {
    private fun fileOf(id: String): File? = if (ID.matches(id)) File(dir, id) else null

    override fun put(id: String, bytes: ByteArray): Boolean = runCatching { fileOf(id)?.let { writeOwnerOnly(it, bytes) } ?: false }.getOrDefault(false)

    /** Null only when there is no such file (or the id is not one this app mints); an I/O error goes through. */
    override fun getOrThrow(id: String): ByteArray? {
        val f = fileOf(id) ?: return null
        return if (!SafeDelete.exists(f)) null else readOrThrow(f)
    }

    override fun get(id: String): ByteArray? = neverThrows("a kept file could not be read") { getOrThrow(id) }

    override fun delete(id: String) {
        fileOf(id)?.delete()
    }

    /** Empty only when the directory does not exist; one that is there and cannot be listed throws. */
    override fun idsOrThrow(): List<String> {
        if (!SafeDelete.exists(dir)) return emptyList()
        val names = dir.list() ?: throw java.io.IOException("${dir.name} is there but could not be listed")
        return names.filter { ID.matches(it) }
    }

    override fun ids(): List<String> = neverThrows("kept files could not be listed") { idsOrThrow() } ?: emptyList()

    override fun clear() {
        SafeDelete.tree(dir, within)
    }

    private companion object {
        val ID = Regex("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
    }
}

/** A [FileRecord] while [keepOnDisk], memory otherwise; with both readers. */
internal class OptInRecord(file: File, private val keepOnDisk: () -> Boolean) : FillSnapshotStore, StrictRecordStore {
    private val disk = FileRecord(file)
    private val memory = InMemoryFillSnapshots()

    @Synchronized
    override fun write(bytes: ByteArray): Boolean = if (keepOnDisk()) disk.write(bytes) else memory.write(bytes)

    @Synchronized
    override fun readOrThrow(): ByteArray? = if (keepOnDisk()) disk.readOrThrow() else memory.read()

    @Synchronized
    override fun read(): ByteArray? = if (keepOnDisk()) disk.read() else memory.read()

    @Synchronized
    override fun delete() {
        disk.delete()
        memory.delete()
    }

    /** What the file holds goes to memory as well; the file stays. One that cannot be read is logged and not carried. */
    @Synchronized
    fun copyToMemory() {
        runCatching { disk.readOrThrow() }
            .onSuccess { b -> b?.let { memory.write(it) } }
            .onFailure { io.silencelen.andvari.desktop.DesktopDiagnostics.logThrowable("a kept record could not be read before the switch-off", it) }
    }

    @Synchronized
    fun keepChanged(on: Boolean) {
        if (on) {
            memory.read()?.let { if (disk.write(it)) memory.delete() }
        } else {
            // A record that cannot be read cannot be carried into memory; the person's switch-off still removes the
            // file (that is what it asks for), and the loss is logged, never silent.
            runCatching { disk.readOrThrow() }
                .onSuccess { b -> b?.let { memory.write(it) } }
                .onFailure { io.silencelen.andvari.desktop.DesktopDiagnostics.logThrowable("a kept record could not be read at the switch-off", it) }
            disk.delete()
        }
    }
}

/** [FileBlobs] while [keepOnDisk], memory otherwise; with both readers. */
internal class OptInBlobs(dir: File, within: File, private val keepOnDisk: () -> Boolean) : BlobStore, StrictBlobStore {
    private val disk = FileBlobs(dir, within)
    private val memory = InMemoryBlobs()

    private fun side(): BlobStore = if (keepOnDisk()) disk else memory

    @Synchronized
    override fun put(id: String, bytes: ByteArray): Boolean = side().put(id, bytes)

    @Synchronized
    override fun get(id: String): ByteArray? = side().get(id)

    @Synchronized
    override fun getOrThrow(id: String): ByteArray? = if (keepOnDisk()) disk.getOrThrow(id) else memory.get(id)

    @Synchronized
    override fun delete(id: String) = side().delete(id)

    @Synchronized
    override fun ids(): List<String> = side().ids()

    @Synchronized
    override fun idsOrThrow(): List<String> = if (keepOnDisk()) disk.idsOrThrow() else memory.ids()

    @Synchronized
    override fun clear() {
        disk.clear()
        memory.clear()
    }

    /** Every file on disk is copied to memory as well; the files stay. What cannot be read is logged and not carried. */
    @Synchronized
    fun copyToMemory() {
        val ids = runCatching { disk.idsOrThrow() }.onFailure { io.silencelen.andvari.desktop.DesktopDiagnostics.logThrowable("kept files could not be listed before the switch-off", it) }.getOrDefault(emptyList())
        for (id in ids) {
            val bytes = runCatching { disk.getOrThrow(id) }.onFailure { io.silencelen.andvari.desktop.DesktopDiagnostics.logThrowable("a kept file could not be read before the switch-off", it) }.getOrNull() ?: continue
            memory.put(id, bytes)
            bytes.fill(0)
        }
    }

    @Synchronized
    fun keepChanged(on: Boolean) {
        val (from, to) = if (on) memory to disk else disk to memory
        // As in [OptInRecord.keepChanged]: what cannot be read is not carried, and that is logged; it is never moved
        // as if it were empty. The disk side is read with its strict readers.
        fun ids(): List<String> = if (from === disk) disk.idsOrThrow() else from.ids()
        fun get(id: String): ByteArray? = if (from === disk) disk.getOrThrow(id) else from.get(id)
        val ids = runCatching { ids() }.onFailure { io.silencelen.andvari.desktop.DesktopDiagnostics.logThrowable("kept files could not be listed at the switch", it) }.getOrDefault(emptyList())
        for (id in ids) {
            val bytes = runCatching { get(id) }.onFailure { io.silencelen.andvari.desktop.DesktopDiagnostics.logThrowable("a kept file could not be read at the switch", it) }.getOrNull() ?: continue
            if (to.put(id, bytes)) from.delete(id)
            bytes.fill(0)
        }
        if (!on) disk.clear()
    }
}

/**
 * A plain reader over a strict one: core's old readers promise never to throw, so a read error is logged (redacted,
 * naming the file only) and answers null. Core reads the strict readers wherever "nothing there" would matter.
 */
private inline fun <T> neverThrows(what: String, read: () -> T?): T? =
    try {
        read()
    } catch (e: Exception) {
        runCatching { io.silencelen.andvari.desktop.DesktopDiagnostics.logThrowable(what, e) }
        null
    }

/** The bytes of [f], which is there: any failure to read them is thrown, naming the file only. */
private fun readOrThrow(f: File): ByteArray =
    try {
        f.readBytes()
    } catch (e: java.io.IOException) {
        throw java.io.IOException("${f.name} is there but could not be read", e)
    }

/** Written beside [target] as an owner-only file of its own name, then renamed over it. Returns whether it was written. */
private fun writeOwnerOnly(target: File, bytes: ByteArray): Boolean {
    replaceOwnerOnly(target, bytes)
    return true
}
