package io.silencelen.andvari.desktop.trust

import java.io.File
import java.io.IOException
import java.nio.channels.FileChannel
import java.nio.channels.FileLock
import java.nio.channels.OverlappingFileLockException
import java.nio.file.StandardOpenOption

/**
 * One andvari per account on this computer. Two instances held the same refresh token,
 * so the server ended the device's session (`refresh_reuse`), and both rewrote `device-state.json`.
 *
 * [acquire] takes an exclusive lock with [FileChannel.tryLock] on a file in `v2/`, before anything else of the app
 * runs: before the native library is staged, before the diagnostics, before any store is read. The lock lives as long
 * as the process (the OS drops it when the process ends, a crash included). A second start gets [Gate.AlreadyOpen],
 * says so and exits.
 */
class SingleInstance private constructor(private val channel: FileChannel, private val lock: FileLock) {
    /** What a start found. */
    sealed interface Gate {
        /** This process is the only one; keep [instance] for the life of the process. */
        class Acquired(val instance: SingleInstance) : Gate

        /** Another andvari holds the lock. */
        data object AlreadyOpen : Gate

        /**
         * The lock could not be taken or refused (a file system without locks, a directory that cannot be written). The
         * app cannot tell whether another one is open, so it does not start: the safer reading (nothing is read or
         * written, nothing is lost by not starting).
         */
        class Failed(val why: String) : Gate
    }

    /** Drops the lock (tests; the process's end drops it otherwise). */
    fun release() {
        runCatching { lock.release() }
        runCatching { channel.close() }
    }

    companion object {
        /** The lock file's name in `v2/`. It holds nothing; only its lock counts. */
        const val FILE_NAME = "instance.lock"

        /** The lock file for the app's root [root] (`~/.andvari-desktop`). */
        fun fileIn(root: File): File = File(File(root, DesktopHome.NEW_DIR), FILE_NAME)

        fun acquire(file: File): Gate {
            val channel = try {
                ownerOnlyDir(file.absoluteFile.parentFile)
                // Created owner-only (it holds nothing, but nothing of the app's under its home is readable by others);
                // one an earlier build created readable is made owner-only too.
                FileChannel.open(file.toPath(), setOf(StandardOpenOption.CREATE, StandardOpenOption.WRITE), *ownerOnlyFileAttrs(file.absoluteFile.parentFile))
                    .also { ownerOnlyFile(file) }
            } catch (e: IOException) {
                return Gate.Failed(e.javaClass.simpleName)
            } catch (e: SecurityException) {
                return Gate.Failed(e.javaClass.simpleName)
            }
            val lock = try {
                channel.tryLock()
            } catch (e: OverlappingFileLockException) {
                // This JVM already holds it: a second start inside one process is still a second start. The channel is
                // left open on purpose: on Linux, closing any channel on the file can drop the lock the other one holds.
                return Gate.AlreadyOpen
            } catch (e: IOException) {
                runCatching { channel.close() }
                return Gate.Failed(e.javaClass.simpleName)
            }
            if (lock == null) {
                runCatching { channel.close() }
                return Gate.AlreadyOpen
            }
            return Gate.Acquired(SingleInstance(channel, lock))
        }
    }
}
