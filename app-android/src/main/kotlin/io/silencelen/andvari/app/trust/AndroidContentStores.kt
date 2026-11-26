package io.silencelen.andvari.app.trust

import io.silencelen.andvari.app.quietly
import io.silencelen.andvari.app.readUnlessAbsent
import io.silencelen.andvari.core.app.BlobStore
import io.silencelen.andvari.core.app.FillSnapshotStore
import io.silencelen.andvari.core.app.content.KeptStorage
import io.silencelen.andvari.core.app.content.StrictBlobStore
import io.silencelen.andvari.core.app.content.StrictRecordStore
import io.silencelen.andvari.core.app.content.StrictSaveQueueStore
import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.nio.file.Files
import java.nio.file.NoSuchFileException
import java.nio.file.StandardCopyOption

/**
 * The content's kept records on Android ([io.silencelen.andvari.core.app.engine.AppEngine.contentStores]): one file
 * per record and one directory per set of files, under [dir] (app-private, `no_backup/ovh/kept`). Core seals every
 * record to its account, names them per (origin, account), and uses these files only while the server's policy allows
 * an offline copy (it deletes them otherwise, and at the person's own end). Made once for the process, in [TrustSeam].
 */
internal class AndroidKeptStorage(private val dir: File) : KeptStorage {
    override fun record(name: String): FillSnapshotStore = KeptFile(File(dir, safe(name)))

    override fun blobs(name: String): BlobStore = KeptBlobs(File(dir, safe(name)))

    internal companion object {
        private val NAME = Regex("^[A-Za-z0-9._-]{1,128}$")

        /** Core's names are hex and dashes; anything else never names a file here. */
        fun safe(name: String): String {
            require(NAME.matches(name) && name != "." && name != "..") { "not a kept record's name" }
            return name
        }
    }
}

/**
 * One kept record: written beside itself, synced, then renamed over the old one, so a reader sees the old record or
 * the new one. [readOrThrow] is null only when there is no file and throws on an I/O error (the content reads through
 * it: "unreadable", never empty); [read] keeps the old promise and never throws.
 */
internal class KeptFile(private val file: File) : FillSnapshotStore, StrictRecordStore {
    override fun write(bytes: ByteArray): Boolean = runCatching { AppFiles.writeReplacing(file, bytes) }.getOrDefault(false)

    override fun readOrThrow(): ByteArray? = readUnlessAbsent({ file.exists() }) { file.readBytes() }

    override fun read(): ByteArray? = quietly(null) { readOrThrow() }

    override fun delete() {
        file.delete()
        AppFiles.tmpOf(file).delete()
    }
}

/**
 * The files set aside for a save, one file per attachment id in [dir]; only an id of the shape core mints names a file.
 * [getOrThrow] is null only for an id with no file and throws when one could not be read; [idsOrThrow] throws when the
 * directory is there but cannot be listed (the carry then stops with everything where it was). The content reads
 * through those; [get] and [ids] keep the old promise and never throw.
 */
internal class KeptBlobs(private val dir: File) : BlobStore, StrictBlobStore {
    private fun fileOf(id: String): File? = if (ID.matches(id)) File(dir, id) else null

    override fun put(id: String, bytes: ByteArray): Boolean =
        runCatching { fileOf(id)?.let { AppFiles.writeReplacing(it, bytes) } ?: false }.getOrDefault(false)

    override fun getOrThrow(id: String): ByteArray? {
        val f = fileOf(id) ?: return null
        return readUnlessAbsent({ f.exists() }) { f.readBytes() }
    }

    override fun get(id: String): ByteArray? = quietly(null) { getOrThrow(id) }

    override fun delete(id: String) {
        fileOf(id)?.let { it.delete(); AppFiles.tmpOf(it).delete() }
    }

    override fun idsOrThrow(): List<String> {
        val names = dir.list() ?: if (!dir.exists()) return emptyList() else throw IOException("the set-aside files could not be listed")
        return names.filter { ID.matches(it) }
    }

    override fun ids(): List<String> = quietly(emptyList()) { idsOrThrow() }

    override fun clear() {
        dir.deleteRecursively()
    }

    private companion object {
        val ID = Regex("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
    }
}

/**
 * The extensions' save queue on Android ([io.silencelen.andvari.core.app.content.ContentStores]'s `queue`): the
 * account's published key in `key`, and one file per captured login in `entries/` under [dir] (app-private,
 * `no_backup/ovh/save-queue`). Only this app's own autofill service writes it (no other app can reach app-private
 * files); every entry is sealed to the account's key by core ([io.silencelen.andvari.core.app.SaveQueue.enqueue]), so
 * it holds no plaintext, and the content treats each one as a proposal. An entry is never replaced.
 *
 * [entriesOrThrow] throws when the queue is there but cannot be listed, or a listed entry is there and cannot be read
 * (one removed in between is skipped): the content reads through it and then changes nothing ("unknown is never
 * empty"). [entries] keeps the old promise and never throws: empty when the queue cannot be listed, and an entry it
 * cannot read is left out. The other calls never throw.
 */
internal class AndroidSaveQueue(private val dir: File) : io.silencelen.andvari.core.app.SaveQueueStore, StrictSaveQueueStore {
    private val key = File(dir, "key")
    private val entriesDir = File(dir, "entries")

    override fun publication(): ByteArray? = quietly(null) { readUnlessAbsent({ key.exists() }) { key.readBytes() } }

    override fun publish(bytes: ByteArray?) {
        runCatching { if (bytes == null) { key.delete(); Unit } else AppFiles.writeReplacing(key, bytes) }
    }

    override fun entriesOrThrow(): Map<String, ByteArray> = collect(strict = true)

    override fun entries(): Map<String, ByteArray> = quietly(emptyMap()) { collect(strict = false) }

    private fun collect(strict: Boolean): Map<String, ByteArray> {
        val names = entriesDir.list() ?: if (!entriesDir.exists()) return emptyMap() else throw IOException("the save queue could not be listed")
        val out = LinkedHashMap<String, ByteArray>()
        for (name in names.sorted()) {
            if (!io.silencelen.andvari.core.app.SaveQueue.validId(name)) continue
            val f = File(entriesDir, name)
            val read = { readUnlessAbsent({ f.exists() }) { f.readBytes() } }
            (if (strict) read() else quietly(null, read))?.let { out[name] = it }
        }
        return out
    }

    override fun add(id: String, bytes: ByteArray): Boolean = runCatching {
        if (!io.silencelen.andvari.core.app.SaveQueue.validId(id)) return@runCatching false
        val target = File(entriesDir, id)
        if (target.exists()) return@runCatching false
        if (!entriesDir.isDirectory && !entriesDir.mkdirs() && !entriesDir.isDirectory) return@runCatching false
        val tmp = AppFiles.tmpOf(target)
        try {
            FileOutputStream(tmp).use { out ->
                out.write(bytes)
                out.fd.sync()
            }
            // No REPLACE_EXISTING: an entry already at [id] stays, and this one is not written.
            Files.move(tmp.toPath(), target.toPath())
            true
        } catch (e: IOException) {
            tmp.delete()
            false
        }
    }.getOrDefault(false)

    override fun remove(id: String) {
        if (io.silencelen.andvari.core.app.SaveQueue.validId(id)) runCatching { File(entriesDir, id).delete() }
    }

    override fun clear() {
        runCatching { entriesDir.deleteRecursively() }
        runCatching { key.delete() }
    }
}

/** The file calls the stores and the vault cache share. */
internal object AppFiles {
    fun tmpOf(target: File): File = File(target.absoluteFile.parentFile, target.name + ".tmp")

    /** [bytes] to [target], replacing it only once they are written and synced. True when written; throws otherwise. */
    fun writeReplacing(target: File, bytes: ByteArray): Boolean {
        val parent = target.absoluteFile.parentFile
        if (!parent.isDirectory && !parent.mkdirs() && !parent.isDirectory) throw IOException("no directory for the record")
        val tmp = tmpOf(target)
        try {
            FileOutputStream(tmp).use { out ->
                out.write(bytes)
                out.fd.sync()
            }
            Files.move(tmp.toPath(), target.toPath(), StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE)
        } catch (e: Throwable) {
            tmp.delete()
            throw e
        }
        return true
    }

    /**
     * The vault cache's rename for a followed move ([io.silencelen.andvari.core.app.engine.VaultCacheFiles.rename]):
     * true once [from] is at [to], or when there is no [from]; false, with both names as they were, when a file is
     * already at [to] or the rename failed. Never replaces a file.
     */
    fun moveWithoutReplacing(from: String, to: String): Boolean {
        val a = File(from)
        val b = File(to)
        if (!a.exists()) return true
        if (b.exists()) return false
        return try {
            // No REPLACE_EXISTING: a file at [to] makes this throw rather than be replaced. Same directory: a rename.
            Files.move(a.toPath(), b.toPath())
            true
        } catch (e: NoSuchFileException) {
            !a.exists() && b.exists()
        } catch (e: IOException) {
            false
        }
    }

    /** The vault cache's delete of one path: true when nothing is left at it. */
    fun remove(path: String): Boolean = File(path).let { f -> !f.exists() || f.delete() }
}
