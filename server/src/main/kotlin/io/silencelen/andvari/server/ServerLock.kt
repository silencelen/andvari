package io.silencelen.andvari.server

import java.io.IOException
import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.channels.FileLock
import java.nio.channels.OverlappingFileLockException
import java.nio.file.AccessDeniedException
import java.nio.file.FileSystemException
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.OpenOption
import java.nio.file.Path
import java.nio.file.StandardOpenOption
import java.nio.file.attribute.BasicFileAttributes
import java.nio.file.attribute.PosixFilePermissions
import java.security.SecureRandom

/**
 * `server.lock` in the data folder (decided on 2026-11-22): the file whose lock says that a running server holds the
 * database. The lock has two parts, both exclusive, both taken through one opening of the file: the first on the file's
 * first byte, the second on its second byte (the two never overlap). The server's start takes the first part after the
 * database is open and caught up and before the server listens; then it cuts the file, writes one line into it through
 * that opening and forces it to the disk: `server <start> database <file>`, where `<start>` is 32 hexadecimal digits drawn
 * at random at this start and `<file>` is the identity the system gives the database file (its file key: device and
 * inode); then it takes the second part. It keeps both until its process ends, however it ends; the system lets go of
 * them with the process. So a process holds the second part only once it has written its own line, and the line can be
 * written only by a process that holds the first part: where a server holds the second part, the line in the file is
 * that of a server that still runs (the command's look takes shared locks, for an instant only, which never make another
 * look read the line).
 *
 * The identity is read twice: before the database is opened ([keyBeforeOpen]) and when the line is written. Where there
 * was a file at the database's path before the open and the file there at the line is another one, the server lets go of
 * the lock and starts without it: the line would name a file that is not the one this server opened.
 *
 * `andvari admin backup` looks at the lock and its line before it opens the database and again before it names a
 * snapshot, and keeps a snapshot only where both looks find the second part held and the same line, naming the file it
 * opens ([ServerBackup]). A second server on the same folder never holds either part and writes nothing into the file. A
 * server whose database is not a file (`:memory:`) takes no lock and makes no file.
 */
object ServerLock {
    const val NAME = "server.lock"

    /** The database path of a server whose database lives in memory only: it has no file to name. */
    private const val IN_MEMORY = ":memory:"

    /** The server's line, exactly: its start value and the file key of its database file. */
    private val LINE = Regex("server ([0-9a-f]{32}) database (\\S+)\n")

    /** The most a line can be; the command reads no more than one byte past it. */
    const val MOST = 512

    /** The first part of the lock: the file's first byte. It excludes a second server and gives the right to write the line. */
    const val FIRST = 0L

    /** The second part of the lock: the file's second byte, taken only once the line is written. */
    const val SECOND = 1L

    /** How long the start tries for each part: a look of the backup command holds a shared lock on them for an instant only. */
    const val TRY_MS = 2_000L
    private const val PAUSE_MS = 50L

    private val NOFOLLOW = LinkOption.NOFOLLOW_LINKS

    /**
     * The data folder of the database path [dbPath] as configured: the folder of that path, made absolute, a link in the
     * database's own name not followed. The backup command calls this folder the data folder too: its `backup/` and this
     * file lie there.
     */
    fun dataFolder(dbPath: String): Path = Path.of(dbPath).toAbsolutePath().normalize().parent

    /** `server.lock` in the data folder of [dbPath]. */
    fun file(dbPath: String): Path = dataFolder(dbPath).resolve(NAME)

    /**
     * The one opening of `server.lock` in the server's process, kept for the life of the process so that its lock stays.
     * A lock of this kind belongs to the process, not to the opening: closing any other opening of the same file in this
     * process would let go of it. So nothing else in the server's process ever opens that file; the backup command's look
     * runs in a process of its own.
     */
    @Volatile
    private var held: FileChannel? = null

    /**
     * Called by [take] once the line is written and before the second part is taken. Only the tests set it, to look at the
     * file in that instant; the server's program never does, and no setting, variable of the environment or option of a
     * command reaches it.
     */
    @Volatile
    internal var betweenLineAndSecondPart: () -> Unit = {}

    /** For the tests that call [take] more than once in one process: closes the kept opening, which lets go of both parts. */
    internal fun letGoForTests() {
        held?.close()
        held = null
    }

    /**
     * The identity the system gives the database file at [dbPath] (its file key), links followed as the database's own
     * open follows them; null where the system gives none. The server writes it into its line, and the backup command
     * reads it for its own path the same way.
     */
    fun keyOf(dbPath: String): String? =
        Files.readAttributes(Path.of(dbPath), BasicFileAttributes::class.java).fileKey()?.toString()

    /**
     * The identity of the file at [dbPath] as the server's start reads it before it opens the database: null where there
     * is no such file yet, where the database lives in memory, and where it cannot be read (that is no reason to refuse a
     * start; [take] then goes by the identity it reads when it writes the line).
     */
    fun keyBeforeOpen(dbPath: String): String? =
        if (dbPath == IN_MEMORY) null else try { keyOf(dbPath) } catch (e: Exception) { null }

    /** The line a server writes for its start value [start] and its database's file key [key]. */
    internal fun line(start: String, key: String): String = "server $start database $key\n"

    /** The file key that the line [text] names, null where [text] is not a whole line of a server. */
    fun keyIn(text: String): String? = LINE.matchEntire(text)?.groupValues?.get(2)

    /**
     * The server's start takes the lock for its database at [dbPath], in its two parts with its line between them: null
     * when it holds both, else the one warning line to print (the server then starts without it). [before] is the identity
     * of the database file read before the database was opened ([keyBeforeOpen]). In this order: the first part, tried for
     * [TRY_MS] at most; the line, written as [writeLine] says; the second part, tried for [TRY_MS] at most. It never waits
     * without end. The file is made owner-only where it is missing; a link is not followed; a file that exists keeps its
     * mode. Any failure after the first part closes the opening, which lets go of every part it held. A database in memory
     * only: nothing is done and nothing is said.
     */
    internal fun take(dbPath: String, before: String?): String? {
        if (held != null) return null
        if (dbPath == IN_MEMORY) return null
        val p = file(dbPath)
        val why = try {
            when {
                Files.isSymbolicLink(p) -> "it is a link, and the server follows no link to it"
                Files.exists(p, NOFOLLOW) && !Files.isRegularFile(p, NOFOLLOW) -> "it is not an ordinary file"
                else -> {
                    val options = setOf<OpenOption>(StandardOpenOption.CREATE, StandardOpenOption.WRITE, NOFOLLOW)
                    val channel = FileChannel.open(p, options, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")))
                    var kept = false
                    try {
                        val refused = tryFor(channel, FIRST, "another process holds it")
                            ?: writeLine(channel, dbPath, before)
                            ?: run {
                                betweenLineAndSecondPart()
                                tryFor(channel, SECOND, "another process holds a lock on its second byte")
                            }
                        if (refused == null) {
                            held = channel
                            kept = true
                        }
                        refused ?: return null
                    } finally {
                        // Closing this opening lets go of every part of the lock it held.
                        if (!kept) channel.close()
                    }
                }
            }
        } catch (e: IOException) {
            "it could not be opened for writing: ${reason(e)}"
        }
        return "[andvari] WARNING: the server could not take the lock on $p ($why) and starts without it. " +
            "`andvari admin backup` takes a snapshot only while a process holds the lock on that file."
    }

    /**
     * Writes the server's line into the file through [channel], the opening that holds the first part of the lock (any
     * other opening of the file in this process would let go of the lock when it closes): the identity of the database
     * file is read again, and where [before] (the one read before the database was opened) is there and differs, nothing
     * is written; else the file is cut, the line written from its start, and forced to the disk. Null when it is written,
     * else why not.
     */
    private fun writeLine(channel: FileChannel, dbPath: String, before: String?): String? {
        val key = try {
            keyOf(dbPath)
        } catch (e: IOException) {
            return "the identity of the database file $dbPath could not be read: ${reason(e)}"
        } ?: return "the system gives the database file $dbPath no identity to write into it"
        if (before != null && before != key) return "the file at $dbPath is not the one that was there before the server opened its database"
        val start = ByteArray(16).also { SecureRandom().nextBytes(it) }.joinToString("") { "%02x".format(it) }
        val bytes = ByteBuffer.wrap(line(start, key).encodeToByteArray())
        return try {
            channel.truncate(0)
            var at = 0L
            while (bytes.hasRemaining()) at += channel.write(bytes, at)
            channel.force(true)
            null
        } catch (e: IOException) {
            "its line could not be written into it: ${reason(e)}"
        }
    }

    /**
     * Tries for the exclusive lock on the one byte at [position] of [channel] for [TRY_MS]: null when it is held, else why
     * not ([taken] where another process holds a lock there all that time).
     */
    private fun tryFor(channel: FileChannel, position: Long, taken: String): String? {
        val end = System.nanoTime() + TRY_MS * 1_000_000
        while (true) {
            val lock: FileLock? = try {
                channel.tryLock(position, 1L, false)
            } catch (e: OverlappingFileLockException) {
                null
            } catch (e: IOException) {
                return "the file system refused the lock: ${reason(e)}"
            }
            if (lock != null) return null
            if (System.nanoTime() >= end) return taken
            Thread.sleep(PAUSE_MS)
        }
    }

    /** What the system said of [e], in a few words. */
    internal fun reason(e: IOException): String = when (e) {
        is AccessDeniedException -> "permission denied"
        is FileSystemException -> e.reason ?: e.javaClass.simpleName
        else -> e.message ?: e.javaClass.simpleName
    }
}
