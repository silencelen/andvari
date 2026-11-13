package io.silencelen.andvari.app

import android.util.AtomicFile
import io.silencelen.andvari.core.app.FillSnapshotStore
import java.io.File

/**
 * A small file in the app's own storage, replaced whole (AtomicFile: a write that fails leaves the previous one). Holds
 * what the core seals before it gets here (VaultMoves keeps an unfinished move in one, sealed to the account).
 */
internal class AppPrivateFile(private val file: File) : FillSnapshotStore {
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

    override fun read(): ByteArray? = runCatching { if (file.exists()) atomic.readFully() else null }.getOrNull()

    override fun delete() {
        runCatching { atomic.delete() }
    }
}
