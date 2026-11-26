package io.silencelen.andvari.cli

import java.io.File
import java.nio.channels.FileChannel
import java.nio.channels.FileLock
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.StandardOpenOption
import java.nio.file.attribute.PosixFilePermissions
import java.util.concurrent.ConcurrentHashMap

/**
 * One andvari-cli command at a time in a home. Every command that opens the home holds this lock from before it reads
 * anything there until it ends: what it decides on (the saved sessions, which account an address is, the record of a key,
 * a pin) cannot change under it, and what it writes is not written back over another command's later change. There is no
 * command that only reads: reading a pin finishes a move of it that was cut short, and opening the home finishes a
 * forgetting a stopped run began.
 *
 * It is the system's lock on the file [FILE_NAME] in the home ([FileChannel.tryLock]). The system drops it when the process
 * that holds it ends in any way, a kill included, so a lock left by a process that died never blocks; the file itself
 * stays and means nothing. A second command asks again every [POLL_MS] for at most [waitMs] and then stops, having read
 * and changed nothing ([homeBusyError]).
 */
class HomeLock private constructor(private val key: String, private val channel: FileChannel, private val lock: FileLock) : AutoCloseable {
    override fun close() {
        try {
            runCatching { lock.release() }
            runCatching { channel.close() }
        } finally {
            held.remove(key)
        }
    }

    companion object {
        const val FILE_NAME = "andvari-cli.lock"

        /**
         * How long a command waits for another in the same home: long enough for an ordinary command (a sign-in's key
         * derivation, a sync) to end, so that two commands a script starts together run one after the other; short enough
         * that nobody is left wondering. A command that waits for a person (a device link, a password typed at a prompt)
         * holds the home longer, and a second command then stops and says so.
         */
        const val WAIT_MS = 10_000L

        /** The environment variable that sets another wait, in milliseconds, from 0 up to [WAIT_MAX_MS]: never an endless one. */
        const val WAIT_ENV = "ANDVARI_CLI_LOCK_WAIT_MS"
        const val WAIT_MAX_MS = 60_000L
        private const val POLL_MS = 50L

        /**
         * The homes this process holds. Two channels of one process on the same file must never be open at once: closing
         * either drops the process's lock on it (that is how the system's file locks work), so the lock is asked for only
         * by the one that claimed the home here first.
         */
        private val held: MutableSet<String> = ConcurrentHashMap.newKeySet()

        /** The wait [env] names ([WAIT_ENV]), else [WAIT_MS]. */
        fun waitMs(env: (String) -> String?): Long = env(WAIT_ENV)?.trim()?.toLongOrNull()?.coerceIn(0, WAIT_MAX_MS) ?: WAIT_MS

        /** The lock of the home [dir], or null when another command held it for the whole of [waitMs]. */
        fun take(dir: File, waitMs: Long): HomeLock? {
            val path = File(dir, FILE_NAME).toPath().toAbsolutePath().normalize()
            val key = path.toString()
            val deadline = System.nanoTime() + waitMs * 1_000_000
            while (true) {
                if (held.add(key)) {
                    var ch: FileChannel? = null
                    try {
                        ch = open(path)
                        ch.tryLock()?.let { return HomeLock(key, ch, it) }
                        ch.close()
                        held.remove(key)
                    } catch (e: Exception) {
                        runCatching { ch?.close() }
                        held.remove(key)
                        throw CliError(fill(HOME_NOT_LOCKED, dir.path, e.message ?: e.javaClass.simpleName), 1, KEY_HOME_NOT_LOCKED)
                    }
                }
                if (System.nanoTime() - deadline >= 0) return null
                Thread.sleep(POLL_MS)
            }
        }

        private fun open(path: Path): FileChannel {
            val options = setOf(StandardOpenOption.CREATE, StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS)
            val posix = runCatching { Files.getFileStore(path.parent).supportsFileAttributeView("posix") }.getOrDefault(false)
            return if (posix) FileChannel.open(path, options, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")))
            else FileChannel.open(path, options)
        }
    }
}

/** The message key of [HOME_NOT_LOCKED]. */
const val KEY_HOME_NOT_LOCKED = "home_not_locked"

/**
 * The home's lock file could not be opened or locked (the tool's own sentence, not yet on the wording page): nothing was
 * sent or changed. `{0}` the home, `{1}` what the system said.
 */
const val HOME_NOT_LOCKED = "this device could not lock its home {0} ({1}), so nothing was sent and nothing was changed"

/** The message key and exit code of [HOME_BUSY]. */
const val KEY_HOME_BUSY = "home_busy"
const val EXIT_HOME_BUSY = 8

/**
 * Another command held the home for the whole wait (the tool's own sentence, not yet on the wording page). It must say: another
 * andvari-cli command is running in this home; how long this one waited; that it sent nothing and changed nothing; to run it
 * again when the other has finished. `{0}` the home, `{1}` the wait.
 */
const val HOME_BUSY = "Another andvari-cli command is running in this home ({0}). This one waited {1} for it and then stopped: " +
    "it sent nothing and changed nothing on this device. Run it again when the other command has finished."

/** [HOME_BUSY] for the home [dir] after [waitMs], with its exit code and key. */
fun homeBusyError(dir: File, waitMs: Long): CliError =
    CliError(fill(HOME_BUSY, dir.path, if (waitMs % 1000 == 0L) seconds(waitMs / 1000) else "$waitMs milliseconds"), EXIT_HOME_BUSY, KEY_HOME_BUSY)
