package io.silencelen.andvari.app

import android.util.AtomicFile
import io.silencelen.andvari.core.app.FillSnapshotStore
import io.silencelen.andvari.core.app.content.StrictRecordStore
import java.io.File
import java.io.FileNotFoundException

/**
 * A small file in the app's own storage, replaced whole (AtomicFile: a write that fails leaves the previous one). Holds
 * what the core seals before it gets here (VaultMoves keeps an unfinished move in one, sealed to the account).
 *
 * [readOrThrow] answers null only when there is no file and throws on an I/O error, so a reader that asks it never
 * takes a record that could not be read for an empty one. [read] keeps the shared code's old promise and never throws
 * (null for no file and for one it could not read): the store's own readers and the extensions rely on that.
 */
internal class AppPrivateFile(private val file: File) : FillSnapshotStore, StrictRecordStore {
    private val atomic = AtomicFile(file)

    override fun write(bytes: ByteArray): Boolean = runCatching {
        file.parentFile?.mkdirs()
        val out = atomic.startWrite()
        try {
            out.write(bytes)
            atomic.finishWrite(out)
        } catch (t: Throwable) {
            atomic.failWrite(out)
            throw t
        }
        true
    }.getOrDefault(false)

    // AtomicFile restores a backup a crashed write left behind, so the file is asked after the attempt, not before.
    override fun readOrThrow(): ByteArray? = readUnlessAbsent({ file.exists() }) { atomic.readFully() }

    override fun read(): ByteArray? = quietly(null) { readOrThrow() }

    override fun delete() {
        runCatching { atomic.delete() }
    }
}

/**
 * The old readers' promise ("never throws"): [read]'s answer, or [fallback] when it threw. Only the plain readers use
 * it; the strict ones beside them pass every failure on.
 */
internal inline fun <T> quietly(fallback: T, read: () -> T): T = try {
    read()
} catch (e: Exception) {
    fallback
}

/**
 * The read rule for every kept record on Android: [read]'s bytes; null only when the read found no file and [exists]
 * agrees after it; every other failure (a file that is there but cannot be opened, an I/O error, a directory in its
 * place) is thrown. `FileNotFoundException` is also how Java reports a permission refused, hence the second look.
 */
internal fun readUnlessAbsent(exists: () -> Boolean, read: () -> ByteArray): ByteArray? = try {
    read()
} catch (e: FileNotFoundException) {
    if (exists()) throw e
    null
}
