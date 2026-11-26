package io.silencelen.andvari.server

import org.sqlite.SQLiteConfig
import java.io.File
import java.io.IOException
import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.channels.FileLock
import java.nio.channels.OverlappingFileLockException
import java.nio.file.FileAlreadyExistsException
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.NoSuchFileException
import java.nio.file.OpenOption
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.nio.file.StandardOpenOption
import java.nio.file.attribute.PosixFilePermissions
import java.sql.Connection
import java.sql.DriverManager
import java.sql.SQLException
import java.time.Instant
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter

/**
 * `andvari admin backup [--keep N]` (decided on 2026-11-22): the nightly snapshot of the database, as a command of the
 * server. It runs the way every admin command runs (in the server's image, as the server's user), and it keeps a
 * snapshot only where it finds the server's lock held for the database file it opens, before it opens it and again
 * before it names the snapshot; it opens the database for reading only. The host needs no program of its own for it, and nothing of
 * it runs as root. It never starts the server and opens no network connection. It reads the server's settings file and
 * prints none of the warnings the server's start prints about those settings: they belong to the start.
 *
 * What one run does, in this order, each step named in the line of a run that fails there:
 *
 * 1. **The server.** Before anything reads or opens the database and before the backup folder is made, the command looks
 *    at `server.lock` in the data folder ([ServerLock]), on which the server's start takes a lock in two parts that it
 *    keeps until its process ends (the first on the file's first byte, the second on its second byte, taken only once
 *    the server has written into the file the one line naming its database file): it opens that file for reading, never
 *    making it and following no link, and tries shared locks without waiting. Where the file is missing or a shared lock
 *    over both parts is had, no process holds the lock: the command lets go and stops, having opened, made and changed
 *    nothing else. Where a part of the lock is held and the second part is not, the command cannot tell and stops too.
 *    Where the second part is held, the command reads the line through the same opening, and goes on only where the
 *    line names the database file at its own path (the same file key, links followed as the database's open follows
 *    them). A line that names no database file (a damaged one), a line that names another file (another database in the
 *    folder, a second name of another folder's lock file, a database file replaced by a new one), a file that cannot be
 *    looked at (a link, not an ordinary file, one that cannot be opened for reading) and a file system that refuses the
 *    lock stop the run here too: the command does not guess and does not wait. Two runs' looks are both shared, so a
 *    run never takes another run for a server.
 * 2. **The database.** The header of the database file, read as bytes and not opened, must say write-ahead mode, the
 *    mode the server keeps its database in from its start; a header that does not, with a rollback journal beside it or
 *    none, is refused with one plain line. Then the leftover guard ([Db.refuseForeignWriteAhead]); then a rollback journal
 *    beside the database (`andvari.db-journal`) is refused before anything opens the database, since the first open
 *    after the server has stopped, the server's own next start included, applies it: the line names only the journal
 *    and says to move it out of the data folder. Then the command opens its one connection to the database, in the
 *    driver's read-only open mode: the system opens the database file for reading only, so neither this connection nor
 *    its close can write into it, whatever a look missed (SQLite may still make and write the `-shm` file beside it, and
 *    makes an empty `-wal` where none is there). Then the start's decision ([Db.decide]), on that connection: a database
 *    the server's start would refuse is refused with the start's own sentence. Neither the start's change of the journal
 *    mode nor its catch-up is done: the command adds no row and no table and leaves the journal mode as it is.
 * 3. **The backup folder**, `backup/` in the data folder (the folder of the database's path as configured; a link in
 *    the database's own name is not followed for this, so the folder lies where the guide's restore lines name it). It
 *    must be a real folder, not a link and not a file; a missing one is made, owner-only.
 * 4. **The lock**, `backup/backup.lock`: one run at a time. The lock ends with the process that holds it, however it
 *    ends, so the file a run leaves blocks no later run. A second run while one works is refused.
 * 5. **The names in the backup folder.** The nightly name and the temporary names must be ordinary files where they
 *    exist: a link or a folder in their place is refused and left as it is. What a killed run left under the temporary
 *    names (the file and the `-journal`, `-wal` and `-shm` beside it), when it is an ordinary file, is removed.
 * 6. **The room.** The file system that holds the backup folder must have at least twice the size of the database and
 *    its write-ahead file free.
 * 7. **The snapshot**: `VACUUM INTO` the temporary name, a file the command makes new, owner-only. In write-ahead mode
 *    this reads one committed state while the running server goes on writing.
 * 8. **The check of the snapshot**: not empty, it opens, the integrity check answers exactly ok, and it holds this
 *    build's marker; then it is written to the disk. Where the snapshot or its check fails, the command looks at the lock
 *    once more, as at step 9, before it prints its line: where the lock is not held as it was at step 1, the line says so
 *    before its end (the files it read may have been moved or replaced while it read them), and the failure's own words
 *    stay in it.
 * 9. **The server, looked at again**: the same look as step 1, which must find the second part held and the same line in the
 *    file as at step 1 (a server that stopped meanwhile, or a stop, a restore and a new start within the run, which
 *    writes a line of its own, does not pass). Where it does not, the temporary snapshot is removed, and no name is given.
 * 10. **The dated name**, `andvari-nightly-YYYY-MM-DD-HHMMSS.db` (the time in UTC, so that no hour repeats when the
 *    clocks change): a second name of the same file, which must not exist yet; a dated snapshot is never written over.
 * 11. **The nightly name**, `andvari-nightly.db`, by one rename: the only name the command ever writes over.
 * 12. **The removal of old snapshots**: the newest N dated snapshots stay (14, or `--keep N` from 1 to 999), tonight's
 *    always among them whatever its date, the others newest by the date in their names (`--keep` given twice, in
 *    either spelling, is refused at the arguments, like every form the command does not know). Only ordinary files whose
 *    names match the dated pattern exactly are ever removed.
 *
 * A server that stops after the first look while the run works leaves the command reading, for reading only, the
 * database of a server that no longer runs: its connection changes no byte of the database file, and the second look
 * keeps the snapshot from any name.
 *
 * A run that works prints nothing and ends with status 0. A run that fails prints exactly one line, which names the step,
 * and ends with status 1, an error nobody foresaw included; a run that fails removes its own temporary file. There is no
 * snapshot under a name of the operator's choosing.
 */
object ServerBackup {
    const val FOLDER = "backup"
    const val NIGHTLY = "andvari-nightly.db"
    const val TEMPORARY = "andvari-nightly.db.tmp"
    const val LOCK = "backup.lock"
    const val DEFAULT_KEEP = 14

    /** The names of the dated snapshots, exactly: the only names the command removes. */
    val DATED = Regex("andvari-nightly-[0-9]{4}-[0-9]{2}-[0-9]{2}-[0-9]{6}\\.db")

    /** The temporary name and the files SQLite may make beside it: a killed run can leave each of them. */
    val TEMPORARY_FAMILY = listOf(TEMPORARY, "$TEMPORARY-journal", "$TEMPORARY-wal", "$TEMPORARY-shm")

    /** A whole number from 1 to 999, written without a sign or a leading zero. */
    private val KEEP = Regex("[1-9][0-9]{0,2}")

    const val USAGE = "usage: andvari admin backup [--keep N], where N is a whole number from 1 to 999 (14 when it is left out)"

    private val STAMP = DateTimeFormatter.ofPattern("uuuu-MM-dd-HHmmss").withZone(ZoneOffset.UTC)

    private val NOFOLLOW = LinkOption.NOFOLLOW_LINKS
    private val OWNER_ONLY_FILE = PosixFilePermissions.fromString("rw-------")
    private val OWNER_ONLY_FOLDER = PosixFilePermissions.fromString("rwx------")

    /** The steps of a run, in the words its line names them by. */
    enum class Step(val words: String) {
        ARGUMENTS("its arguments"),
        SETTINGS("the server's settings"),
        SERVER("the server"),
        DATABASE("the database"),
        FOLDER("the backup folder"),
        LOCK("the lock"),
        NAMES("the names in the backup folder"),
        ROOM("the room"),
        SNAPSHOT("the snapshot"),
        CHECK("the check of the snapshot"),
        AGAIN("the server, looked at again"),
        DATED("the dated name"),
        NIGHTLY("the nightly name"),
        KEEPING("the removal of old snapshots"),
    }

    /**
     * What a test may set: [freeRoom], the free room measured on the backup folder's file system; [atStep], called as each
     * step begins; [serverHolds], true to tell the run that a running server holds the database, so that neither look at
     * `server.lock` is made (for the tests of the later steps that run in one process, where no server can be the
     * holder); [looking], called while a look holds its shared lock; and [opened], called once the connection to the
     * database is open, before its first read. The command line uses the defaults: the file system's own number, nothing,
     * the real looks, nothing and nothing.
     */
    class Seams(
        val freeRoom: (Path) -> Long = { Files.getFileStore(it).usableSpace },
        val atStep: (Step) -> Unit = {},
        val serverHolds: Boolean = false,
        val looking: () -> Unit = {},
        val opened: () -> Unit = {},
    )

    /** The dated name of a snapshot taken at [nowMs]. */
    fun datedName(nowMs: Long): String = "andvari-nightly-${STAMP.format(Instant.ofEpochMilli(nowMs))}.db"

    /**
     * The command, from the arguments of `andvari admin` ([a], its first word `backup`) and the env file [envFile]. Returns
     * when the run worked; otherwise throws [HostCli.Refused] with the run's one line, whatever went wrong.
     */
    fun command(a: HostCli.Args, envFile: File, seams: Seams = Seams()) {
        val at = Progress(seams)
        try {
            val keep = keepOf(a)
            at.enter(Step.SETTINGS)
            // The warnings about the settings belong to the server's start: a run that works prints nothing.
            val config = HostCli.configFrom(envFile) {}
            val now = clockFor(config).now()
            Run(config.dbPath, now, keep, at).go()
        } catch (t: Throwable) {
            throw HostCli.Refused(oneLine("backup stopped at ${at.step.words}: ${what(t)}"))
        }
    }

    /** What went wrong, in the words of the line: the command's own sentence, or what the failure was. */
    private fun what(t: Throwable): String = when (t) {
        is Stop, is HostCli.Refused, is ConfigError -> t.message ?: t.toString()
        is IncompatibleDatabase -> "the server would not start on this database, so no snapshot was taken: ${t.message}"
        else -> "an error nobody foresaw (${t.javaClass.simpleName}: ${t.message})"
    }

    /**
     * The refusal when a rollback journal lies beside the database file named [name], whose header says write-ahead mode
     * (a header that does not is refused before, with its own line). The server switches its database to write-ahead mode
     * at its start and keeps it there: the database's saves are in the file and its own write-ahead file, and the first
     * open after the server has stopped would apply the journal to them, so the line says to move the journal out of the
     * data folder. When the database's path is a link, [link] is (the path, the file it leads to), said first.
     */
    private fun besideAJournal(name: String, link: Pair<String, String>?): String =
        (link?.let { (path, file) -> "$path is a link to $file: the file named here lies beside that file. " } ?: "") +
            "$name-journal lies beside the database. The database file's header says write-ahead mode, the mode the server " +
            "keeps it in. The first open of the database after the server has stopped, the server's own next start " +
            "included, can apply that file to the database, so this command does not open it. No snapshot was taken, and " +
            "nothing was changed. Move this file out of the data folder and keep it, before the server is stopped or " +
            "started; then run this command again."

    /** The refusal when the header of the database file does not say write-ahead mode: [named] is the database file. */
    private fun notWriteAhead(named: String): String =
        "the header of the database file $named does not say write-ahead mode. No snapshot was taken, and nothing was changed."

    private fun oneLine(s: String) = s.replace(Regex("\\s*[\\r\\n]+\\s*"), " ")

    private class Stop(message: String) : Exception(message)

    private fun stop(message: String): Nothing = throw Stop(message)

    private class Progress(val seams: Seams) {
        var step = Step.ARGUMENTS
            private set

        fun enter(s: Step) {
            step = s
            seams.atStep(s)
        }
    }

    /**
     * `--keep N`, once, and nothing else: no word, no other option (there is no named snapshot), no option given twice in
     * any spelling. Checked before anything is done.
     */
    private fun keepOf(a: HostCli.Args): Int {
        a.positional.drop(1).firstOrNull()?.let { stop("there is no named snapshot, and the command takes no word ('$it'); $USAGE. Nothing was done.") }
        val given = a.argv.filter { it.startsWith("--") }.map { it.substring(2).substringBefore('=') }
        given.groupingBy { it }.eachCount().entries.firstOrNull { it.value > 1 }?.let { stop("--${it.key} is given more than once, and the command takes each option once; $USAGE. Nothing was done.") }
        if ("keep" in a.switches) stop("--keep needs its number; $USAGE. Nothing was done.")
        ((a.flags.keys - setOf("keep", "env-file")) + a.switches).firstOrNull()?.let { stop("the command knows no option --$it; $USAGE. Nothing was done.") }
        val k = a.opt("keep") ?: return DEFAULT_KEEP
        if (!KEEP.matches(k)) stop("--keep takes a whole number from 1 to 999, not '$k'; $USAGE. Nothing was done.")
        return k.toInt()
    }

    private class Run(private val path: String, nowMs: Long, private val keep: Int, private val at: Progress) {
        private val dataFolder: Path = ServerLock.dataFolder(path)
        private val folder: Path = dataFolder.resolve(FOLDER)
        private val nightly: Path = folder.resolve(NIGHTLY)
        private val temporary: Path = folder.resolve(TEMPORARY)
        private val lockFile: Path = folder.resolve(LOCK)
        private val dated: Path = folder.resolve(datedName(nowMs))
        private var hadNightly = false

        fun go() {
            at.enter(Step.SERVER)
            if (!at.seams.serverHolds) lookForTheServer()
            at.enter(Step.DATABASE)
            val file = Db.resolved(File(path)) ?: stop(HostCli.cannotOpen(path, Db.UNRESOLVED_LINKS))
            if (!file.isFile) stop("${if (file.exists()) "$path is not a file" else "there is no database at $path"}, so there is nothing to back up; no backup folder was made")
            val link = Db.linkOf(File(path), file)
            // A server that holds the database has it in write-ahead mode from its start: a header that does not say so,
            // read here as bytes from the file the path leads to, is refused before anything opens the database, whatever
            // lies beside it. A header that cannot be read is said as a database that cannot be opened.
            val writeAhead = try {
                Db.headerSaysWriteAhead(file)
            } catch (e: IOException) {
                stop(HostCli.cannotOpen(path, e.message ?: e.toString()))
            }
            if (!writeAhead) stop(notWriteAhead(link?.let { (p, f) -> "$p (a link to $f)" } ?: path))
            Db.refuseForeignWriteAhead(path)
            // A rollback journal beside the database is refused before anything opens it. While the server holds the
            // database open, a new open cannot apply the journal (its first read is refused as busy); the first open after
            // the server has stopped, the server's own next start included, applies it (and a journal of another file
            // damages the database for good). The line names only the journal: beside a running server, the write-ahead
            // file and its `-shm` are the server's own. Nothing is opened, made or changed.
            if (File(file.path + "-journal").exists()) stop(besideAJournal(file.name, link))
            // The one connection to the database, in the driver's read-only open mode: the system opens the file for
            // reading only, so neither this connection nor its close can write into the database, whatever state the
            // looks missed.
            val source = try {
                DriverManager.getConnection("jdbc:sqlite:$path", SQLiteConfig().apply { setReadOnly(true) }.toProperties())
            } catch (e: SQLException) {
                stop(HostCli.databaseFailed(path, e))
            }
            try {
                at.seams.opened()
                try {
                    // Settings of this connection only: none of them writes to the file.
                    source.createStatement().use { st ->
                        st.execute("PRAGMA busy_timeout=5000")
                        st.execute("PRAGMA synchronous=FULL")
                    }
                    if (Db.decide(source)) stop("the database at $path holds no instance yet, so there is nothing to back up; no backup folder was made")
                } catch (e: SQLException) {
                    stop(HostCli.databaseFailed(path, e))
                }
                at.enter(Step.FOLDER)
                makeFolder()
                at.enter(Step.LOCK)
                lock().use {
                    at.enter(Step.NAMES)
                    names()
                    at.enter(Step.ROOM)
                    room(file)
                    snapshot(source)
                    keeping()
                }
            } finally {
                // Closed already after the snapshot; here only on the way out of a run that failed before it, whose own
                // failure is the one the line names.
                runCatching { source.close() }
            }
        }

        /** `server.lock` in the data folder, the file both looks ([look]) look at. */
        private val serverLock: Path = ServerLock.file(path)

        /** The line of the server that held the lock at the first look; null where the seam took the looks out. */
        private var heldLine: String? = null

        /** The first look ([look]), before anything reads or opens the database: its line where it finds no holder. */
        private fun lookForTheServer() {
            heldLine = try {
                look()
            } catch (n: NotHeld) {
                stop(
                    if (n.cannotTell) {
                        "${n.found}, so this command cannot tell whether a running server holds the database. No snapshot was taken, and nothing was changed."
                    } else {
                        "${n.found}. This command looks for a running server by that lock, and takes a snapshot only where it finds the " +
                            "lock held for the database file it would open. No snapshot was taken, and nothing was changed."
                    },
                )
            }
        }

        /**
         * The second look ([look]), once the snapshot is made and checked and before any name is given: the lock is held,
         * with the line of the first look. Where not, the run stops with its line (and its temporary snapshot is removed).
         */
        private fun lookAgain(unchanged: String) {
            val first = heldLine ?: return
            val changed = notAsAtTheFirstLook(first) ?: return
            stop("the snapshot was made and checked, but $changed; tonight's snapshot was not kept, and $unchanged")
        }

        /**
         * A look ([look]) after the first, compared with the first look's line [first]: null where the lock is held with
         * that line; else the words that say it is not, and what the look found, in brackets. The second look's line and
         * the line of a failed snapshot or check ([failed]) both say it in these words.
         */
        private fun notAsAtTheFirstLook(first: String): String? {
            val (cannotTell, found) = try {
                val now = look()
                if (now == first) return null
                false to "a process holds the lock on $serverLock, and the line in that file is not the one this run read before it opened the database"
            } catch (n: NotHeld) {
                n.cannotTell to n.found
            } catch (e: IOException) {
                true to "the look at $serverLock failed (${ServerLock.reason(e)})"
            }
            return (if (cannotTell) "this command cannot tell whether the lock on $serverLock is still held as it was when this run began" else "the lock on $serverLock is no longer held as it was when this run began") +
                " ($found)"
        }

        /**
         * The stop of a failure of the snapshot or of its check, said in its own words [failure], before [unchanged]. Under
         * the same seam as the second look, the lock is looked at once more first ([notAsAtTheFirstLook]): where it is held
         * as it was at the first look, or where the looks are taken out, the line is as the failure has it; where it is
         * not, a clause before [unchanged] says so, since the files this run read may then have been moved or replaced
         * while it read them (a server stopped and a backup put back), and the failure then says nothing certain about the
         * database that is there now. The failure's own words stay in the line whatever the look finds.
         */
        private fun failed(failure: String, unchanged: String): Nothing {
            val first = heldLine
            if (at.seams.serverHolds || first == null) stop("$failure; $unchanged")
            val changed = notAsAtTheFirstLook(first) ?: stop("$failure; $unchanged")
            stop(
                "$failure; $changed, so the database's files may have been moved or replaced while this run read them, and this " +
                    "failure says nothing certain about the database that is there now; $unchanged",
            )
        }

        /** What a look found where it does not go on: what it found, and whether that leaves the command unable to tell. */
        private class NotHeld(val found: String, val cannotTell: Boolean) : Exception(found)

        /**
         * The look at `server.lock` ([ServerLock]): returns the line in the file where a process holds the second part of
         * its lock and that line names the database file at this command's own path (the same file key), else throws
         * [NotHeld]. The file is opened for reading only, never made, no link followed. First a shared lock over both
         * parts at once is tried: obtained, nothing holds the lock. Refused, a shared lock on the second part alone is
         * tried: obtained, the look saw a part of the lock held at its first try and the second part not held at its
         * second, and the command cannot tell (a server's start is so for an instant, between its first part and its
         * second part; a process that ends between the two tries gives the same two answers, though nothing holds any
         * part by then). Refused too, the second part is held, which a server does only once it has written its line: the
         * line is read through the same opening and judged. Each lock is tried once, without waiting, and every lock
         * obtained is let go at once. Nothing is made or changed.
         */
        private fun look(): String {
            val p = serverLock
            fun cannot(found: String): Nothing = throw NotHeld(found, cannotTell = true)
            fun none(found: String): Nothing = throw NotHeld(found, cannotTell = false)
            val missing = "there is no $p, so nothing holds the lock on that file"
            if (Files.isSymbolicLink(p)) cannot("$p is a link, which this command does not follow")
            if (!Files.exists(p, NOFOLLOW)) none(missing)
            if (!Files.isRegularFile(p, NOFOLLOW)) cannot("$p is not an ordinary file")
            val channel = try {
                FileChannel.open(p, StandardOpenOption.READ, NOFOLLOW)
            } catch (e: NoSuchFileException) {
                none(missing)
            } catch (e: IOException) {
                cannot("$p could not be opened for reading (${ServerLock.reason(e)})")
            }
            var firstOnly = false
            val line = channel.use {
                fun shared(position: Long, size: Long): FileLock? = try {
                    it.tryLock(position, size, true)
                } catch (e: OverlappingFileLockException) {
                    cannot("$p is already locked within this command's own process")
                } catch (e: IOException) {
                    cannot("the file system refused a lock on $p (${ServerLock.reason(e)})")
                }
                val both = shared(ServerLock.FIRST, 2L)
                val second = if (both == null) shared(ServerLock.SECOND, 1L) else null
                try {
                    at.seams.looking()
                    firstOnly = both == null && second != null
                    if (both != null || second != null) null else readLine(it)
                } finally {
                    both?.release()
                    second?.release()
                }
            }
            if (firstOnly) cannot("a part of the lock on $p was held when this command looked, and not the second part")
            if (line == null) none("nothing holds the lock on $p")
            val named = ServerLock.keyIn(line) ?: cannot("a process holds the lock on $p, and that file holds no line that names a database file")
            val own = try {
                ServerLock.keyOf(path) ?: cannot("a process holds the lock on $p, and this command could not read which file $path is (the system gives it no identity)")
            } catch (e: NoSuchFileException) {
                cannot("a process holds the lock on $p, and this command could not read which file $path is (there is no such file)")
            } catch (e: IOException) {
                cannot("a process holds the lock on $p, and this command could not read which file $path is (${ServerLock.reason(e)})")
            }
            if (named != own) none("a process holds the lock on $p, and the line in that file names another database file than the one at $path")
            return line
        }

        /** What `server.lock` holds, read through [channel] from its start: at most one byte more than a line can be. */
        private fun readLine(channel: FileChannel): String {
            val buffer = ByteBuffer.allocate(ServerLock.MOST + 1)
            var at = 0L
            while (buffer.hasRemaining()) {
                val n = channel.read(buffer, at)
                if (n < 0) break
                at += n
            }
            return String(buffer.array(), 0, buffer.position(), Charsets.UTF_8)
        }

        private fun makeFolder() {
            val real = "the backup folder must be a real folder inside the data folder $dataFolder"
            if (Files.isSymbolicLink(folder)) stop("$folder is a link, and $real: move the link out of the data folder (the command then makes the folder). Nothing was written.")
            if (Files.exists(folder, NOFOLLOW)) {
                if (!Files.isDirectory(folder, NOFOLLOW)) stop("$folder is not a folder, and $real: move it out of the data folder. Nothing was written.")
                return
            }
            try {
                Files.createDirectory(folder, PosixFilePermissions.asFileAttribute(OWNER_ONLY_FOLDER))
                Files.setPosixFilePermissions(folder, OWNER_ONLY_FOLDER)
            } catch (e: FileAlreadyExistsException) {
                // Made at the same moment by another run: a real folder is as good as one made here.
                if (Files.isSymbolicLink(folder) || !Files.isDirectory(folder, NOFOLLOW)) stop("$folder appeared while it was being made, and it is not a real folder; $real. Nothing was written.")
            } catch (e: IOException) {
                stop("could not make the backup folder $folder (${e.message}). Nothing was written.")
            }
        }

        private fun lock(): FileChannel {
            refuseOdd(lockFile, "Nothing was written.")
            val options = setOf<OpenOption>(StandardOpenOption.CREATE, StandardOpenOption.WRITE, NOFOLLOW)
            val channel = try {
                FileChannel.open(lockFile, options, PosixFilePermissions.asFileAttribute(OWNER_ONLY_FILE))
            } catch (e: IOException) {
                stop("could not open the lock $lockFile (${e.message}). Nothing was written.")
            }
            val held = try {
                channel.tryLock()
            } catch (e: OverlappingFileLockException) {
                null
            } catch (e: IOException) {
                channel.close()
                stop("could not take the lock $lockFile (${e.message}). Nothing was written.")
            }
            if (held == null) {
                channel.close()
                stop("another run of the backup is still working in $folder; this run did nothing.")
            }
            return channel
        }

        /** A link or anything but an ordinary file at [p] is refused, and left as it is. */
        private fun refuseOdd(p: Path, after: String) {
            if (Files.isSymbolicLink(p)) stop("$p is a link, and the command follows no link in the backup folder: move it out of the backup folder. $after")
            if (Files.exists(p, NOFOLLOW) && !Files.isRegularFile(p, NOFOLLOW)) stop("$p is not an ordinary file: move it out of the backup folder. $after")
        }

        private fun names() {
            refuseOdd(nightly, "No snapshot was changed.")
            val family = TEMPORARY_FAMILY.map { folder.resolve(it) }
            for (p in family) refuseOdd(p, "No snapshot was changed.")
            hadNightly = Files.exists(nightly, NOFOLLOW)
            for (p in family) {
                if (!Files.exists(p, NOFOLLOW)) continue
                try {
                    Files.delete(p)
                } catch (e: IOException) {
                    stop("could not remove $p, left by a run that did not finish (${e.message}). No snapshot was changed.")
                }
            }
        }

        private fun room(file: File) {
            val wal = File(file.path + "-wal")
            val size = Files.size(file.toPath()) + (if (wal.isFile) wal.length() else 0L)
            val need = 2 * size
            val free = at.seams.freeRoom(folder)
            if (free < need) {
                stop(
                    "the file system that holds $folder has $free bytes free, and a snapshot needs at least $need bytes free, twice the " +
                        "$size bytes of the database and its write-ahead file. Nothing was written.",
                )
            }
        }

        private fun snapshot(source: Connection) {
            val unchanged = "no earlier snapshot was changed"
            try {
                at.enter(Step.SNAPSHOT)
                try {
                    Files.createFile(temporary, PosixFilePermissions.asFileAttribute(OWNER_ONLY_FILE))
                } catch (e: IOException) {
                    stop("could not make the temporary file $temporary (${e.message}); $unchanged")
                }
                try {
                    source.prepareStatement("VACUUM INTO ?").use { st ->
                        st.setString(1, temporary.toString())
                        st.execute()
                    }
                } catch (e: SQLException) {
                    failed("the snapshot into $temporary failed (${e.message})", unchanged)
                }
                try {
                    source.close()
                } catch (e: SQLException) {
                    failed("the database could not be closed after the snapshot (${e.message})", unchanged)
                }
                at.enter(Step.CHECK)
                check(unchanged)
                at.enter(Step.AGAIN)
                if (!at.seams.serverHolds) lookAgain(unchanged)
                at.enter(Step.DATED)
                try {
                    Files.createLink(dated, temporary)
                } catch (e: FileAlreadyExistsException) {
                    stop("$dated exists already (two runs in one second, or the host's clock went back), and a dated snapshot is never written over; tonight's snapshot was not kept, and $unchanged")
                } catch (e: IOException) {
                    stop("could not give tonight's snapshot the dated name $dated (${e.message}); $unchanged")
                }
            } catch (t: Throwable) {
                val left = removeOwnTemporary() ?: throw t
                throw Stop("${what(t)}; $left")
            }
            try {
                at.enter(Step.NIGHTLY)
                Files.move(temporary, nightly, StandardCopyOption.ATOMIC_MOVE)
            } catch (t: Throwable) {
                val earlier = if (hadNightly) "$nightly is still the earlier snapshot" else "there is no $nightly yet"
                val left = removeOwnTemporary()?.let { "; $it" } ?: ""
                stop("could not give tonight's snapshot the name $nightly (${t.message ?: t.javaClass.simpleName}): tonight's snapshot exists only as $dated, and $earlier$left")
            }
        }

        private fun check(unchanged: String) {
            if (Files.size(temporary) == 0L) failed("the snapshot $temporary is empty", unchanged)
            val readOnly = SQLiteConfig().apply { setReadOnly(true) }.toProperties()
            val (answers, marker) = try {
                DriverManager.getConnection("jdbc:sqlite:$temporary", readOnly).use { c ->
                    val answers = c.queryAll("PRAGMA integrity_check") { it.getString(1) }
                    answers to (if (IntegrityCheck.passed(answers)) c.queryOne("SELECT value FROM meta WHERE key='baseline'") { it.getString(1) } else null)
                }
            } catch (e: SQLException) {
                failed("the snapshot $temporary could not be read for its check (${e.message})", unchanged)
            }
            if (!IntegrityCheck.passed(answers)) failed("the snapshot did not pass the integrity check (it answered: ${answers.take(3).joinToString("; ")})", unchanged)
            if (marker != Db.BASELINE) failed("the snapshot does not hold this build's marker (baseline ${marker ?: "none"}, this build writes ${Db.BASELINE})", unchanged)
            try {
                FileChannel.open(temporary, StandardOpenOption.READ).use { it.force(true) }
            } catch (e: IOException) {
                stop("the snapshot $temporary could not be written to the disk (${e.message}); $unchanged")
            }
        }

        /** Removes what this run made under the temporary names; null when nothing is left, else what is. */
        private fun removeOwnTemporary(): String? {
            val left = ArrayList<String>()
            for (p in TEMPORARY_FAMILY.map { folder.resolve(it) }) {
                if (!Files.exists(p, NOFOLLOW)) continue
                if (Files.isSymbolicLink(p) || !Files.isRegularFile(p, NOFOLLOW)) {
                    left += "$p is not an ordinary file and was left as it is"
                    continue
                }
                try {
                    Files.delete(p)
                } catch (e: IOException) {
                    left += "its temporary file $p could not be removed (${e.message})"
                }
            }
            return left.takeIf { it.isNotEmpty() }?.joinToString("; ")
        }

        private fun keeping() {
            val inPlace = "tonight's snapshot is in place as $nightly and $dated"
            try {
                at.enter(Step.KEEPING)
                val tonight = dated.fileName.toString()
                val names = Files.list(folder).use { s -> s.map { it.fileName.toString() }.filter { DATED.matches(it) }.toList() }
                // Tonight's is one of the [keep] kept whatever its date (a clock that went back); the others, newest by name.
                val past = names.filter { it != tonight }.sortedDescending().drop(keep - 1).sorted()
                for (name in past) {
                    val p = folder.resolve(name)
                    if (!Files.isRegularFile(p, NOFOLLOW)) {
                        stop("$p has the name of a dated snapshot but is not an ordinary file, so it was not removed, nor any newer one past the newest $keep; $inPlace")
                    }
                    try {
                        Files.delete(p)
                    } catch (e: IOException) {
                        stop("could not remove the old snapshot $p (${e.message}); $inPlace")
                    }
                }
            } catch (e: Stop) {
                throw e
            } catch (t: Throwable) {
                throw Stop("${what(t)}; $inPlace")
            }
        }
    }
}
