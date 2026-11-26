package io.silencelen.andvari.server

import io.silencelen.andvari.server.BackupFixture.Ran
import io.silencelen.andvari.server.BackupFixture.Server
import io.silencelen.andvari.server.BackupFixture.Started
import io.silencelen.andvari.server.BackupFixture.connect
import io.silencelen.andvari.server.BackupFixture.exists
import io.silencelen.andvari.server.BackupFixture.newFolder
import io.silencelen.andvari.server.BackupFixture.process
import io.silencelen.andvari.server.BackupFixture.server
import io.silencelen.andvari.server.BackupFixture.startServer
import io.silencelen.andvari.server.BackupFixture.tree
import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.io.RandomAccessFile
import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.nio.file.StandardOpenOption
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlin.test.fail

/**
 * A process that holds exclusive locks on the file named by its first argument, writing nothing into it, until it is
 * killed: both parts of the server's lock (the file's first and second bytes); with the second argument `first`, the
 * first part only, as a server holds it between its first part and its second part; with `second`, the second part
 * only. It prints one line once it holds them.
 */
object HolderOfALock {
    const val HOLDING = "holding the lock"

    @JvmStatic
    fun main(args: Array<String>) {
        val channel = FileChannel.open(Path.of(args[0]), StandardOpenOption.WRITE)
        val mode = args.getOrNull(1)
        if (mode != "second") channel.lock(ServerLock.FIRST, 1L, false)
        if (mode != "first") channel.lock(ServerLock.SECOND, 1L, false)
        println(HOLDING)
        System.out.flush()
        Thread.sleep(TimeUnit.MINUTES.toMillis(10))
        channel.close()
    }
}

/**
 * A process that tries, once each and without waiting, a lock on the first and then the second part of the server's lock
 * on the file named by its first argument (shared with the second argument `shared`, else exclusive), keeps what it
 * obtains until both are tried, and prints one line: `first obtained|refused, second obtained|refused`.
 */
object ProbeOfALock {
    @JvmStatic
    fun main(args: Array<String>) {
        val shared = args[1] == "shared"
        FileChannel.open(Path.of(args[0]), if (shared) StandardOpenOption.READ else StandardOpenOption.WRITE).use { channel ->
            val first = channel.tryLock(ServerLock.FIRST, 1L, shared)
            val second = channel.tryLock(ServerLock.SECOND, 1L, shared)
            println("first ${if (first != null) "obtained" else "refused"}, second ${if (second != null) "obtained" else "refused"}")
            System.out.flush()
        }
    }
}

/**
 * The line the server writes into `server.lock` once it holds its lock, and what `andvari admin backup` does with it
 * (decided on 2026-11-22): the command opens the database for reading only, and it looks at the lock and its line twice,
 * before it opens anything and again once the snapshot is made and checked, before any name is given. Every server here is
 * the real start (`java … MainKt`) in a process of its own, every stop the real signal, every database the real one through
 * the real library. The command runs as a process of its own, except where a test says it runs in this process (the
 * command's own code, beside a server in another process, held at one of its steps by its hook). Only the test of the
 * read-only open without the look takes the seam that tells a run a server holds the database.
 */
class ServerBackupHolderTest {
    private val takesOnly =
        "This command looks for a running server by that lock, and takes a snapshot only where it finds the lock held for the " +
            "database file it would open. No snapshot was taken, and nothing was changed."

    private val cannotTell = "so this command cannot tell whether a running server holds the database. No snapshot was taken, and nothing was changed."

    private fun noHolder(s: Server) = "andvari: backup stopped at the server: nothing holds the lock on ${s.serverLock.path}. $takesOnly\n"

    private fun missing(s: Server) = "andvari: backup stopped at the server: there is no ${s.serverLock.path}, so nothing holds the lock on that file. $takesOnly\n"

    private fun other(s: Server, db: String) =
        "andvari: backup stopped at the server: a process holds the lock on ${s.serverLock.path}, and the line in that file names " +
            "another database file than the one at $db. $takesOnly\n"

    private fun noLine(s: Server) =
        "andvari: backup stopped at the server: a process holds the lock on ${s.serverLock.path}, and that file holds no line that " +
            "names a database file, $cannotTell\n"

    private fun cannotRead(s: Server, db: String, why: String) =
        "andvari: backup stopped at the server: a process holds the lock on ${s.serverLock.path}, and this command could not read " +
            "which file $db is ($why), $cannotTell\n"

    /** The line of a run whose second look finds the lock no longer as it was ([found]), without its "andvari: " and end. */
    private fun again(s: Server, found: String) =
        "backup stopped at the server, looked at again: the snapshot was made and checked, but the lock on ${s.serverLock.path} " +
            "is no longer held as it was when this run began ($found); tonight's snapshot was not kept, and no earlier snapshot was changed"

    /** What the second look found where another start's line is in the file. */
    private fun anotherLine(s: Server) =
        "a process holds the lock on ${s.serverLock.path}, and the line in that file is not the one this run read before it opened the database"

    private val LINE = Regex("server [0-9a-f]{32} database \\(dev=[0-9a-f]+,ino=[0-9]+\\)\n")

    private fun run(s: Server): Ran = process("admin", "backup", "--env-file", s.env.path)

    private fun assertWorked(r: Ran, what: String) {
        assertEquals(listOf(0, "", ""), listOf(r.code, r.out, r.err), "$what: a run that works prints nothing and ends with status 0")
    }

    private fun assertRefused(r: Ran, line: String, what: String) {
        assertEquals(listOf(1, "", line), listOf(r.code, r.out, r.err), "$what: status 1 and the one line")
    }

    private fun <T> withServer(started: Started, block: (Started) -> T): T = try {
        block(started)
    } finally {
        if (started.process.isAlive) started.kill()
    }

    private fun lockWarnings(started: Started) = started.lines().filter { it.startsWith("[andvari] WARNING: the server could not take the lock") }

    /** Every file of the data folder but a running server's own write-ahead and shared-memory files and its mail sink. */
    private fun besideARunningServer(s: Server): Map<String, String> =
        tree(s.data).filterKeys { it != "andvari.db-wal" && it != "andvari.db-shm" && !it.startsWith("mail-sink") }

    private fun record(what: String) = println("record: $what")

    /** What the `restored` command and then the server's start say on the folder of [s]. */
    private fun recordRestoredAndStart(s: Server, what: String) {
        val restored = process("admin", "restored", "--env-file", s.env.path)
        record("$what: admin restored: status ${restored.code}, out <${restored.out.trimEnd()}>, err <${restored.err.trimEnd()}>")
        withServer(startServer(s)) { st ->
            val listening = st.lines().any { it.contains(BackupFixture.LISTENING) } && st.process.isAlive
            record("$what: the start then: listening=$listening, lines ${st.lines().filterNot { it.contains("TEST MODE") || it.contains("*****") }}")
        }
    }

    /** Rows of meta whose key starts with [prefix], in the database [f], read from a copy of it and its files. */
    private fun countOf(f: File, prefix: String): Long =
        connect(BackupFixture.copyAside(f)).use { c -> c.count("SELECT COUNT(*) FROM meta WHERE key LIKE ?", "$prefix%") }

    private fun grow(db: File, rows: Int) {
        connect(db).use { c ->
            c.autoCommit = false
            c.prepareStatement("INSERT INTO meta(key,value) VALUES(?,?)").use { st ->
                for (i in 1..rows) {
                    st.setString(1, "grown $i")
                    st.setString(2, "g$i".padEnd(2000, 'x'))
                    st.addBatch()
                    if (i % 500 == 0) st.executeBatch()
                }
                st.executeBatch()
            }
            c.commit()
        }
    }

    private fun fds(pid: Long): List<String> =
        File("/proc/$pid/fd").listFiles()?.mapNotNull { runCatching { Files.readSymbolicLink(it.toPath()).toString() }.getOrNull() } ?: emptyList()

    private fun signal(sig: String, pid: Long) {
        check(ProcessBuilder("kill", "-$sig", pid.toString()).start().waitFor() == 0) { "kill -$sig $pid" }
    }

    private fun stateOf(pid: Long): String =
        runCatching { File("/proc/$pid/stat").readText().substringAfterLast(")").trim().split(" ")[0] }.getOrDefault("?")

    /**
     * The operator's restore by the guide's steps, the server stopped: the `-wal` and `-shm` moved out of the data folder,
     * then the snapshot [snapshot] written over `andvari.db` in place (the same file, as `cp` writes it). Returns the names
     * in the data folder after these steps.
     */
    private fun restore(s: Server, snapshot: ByteArray): Set<String> {
        val aside = newFolder("operator-aside")
        for (suffix in listOf("-wal", "-shm")) {
            val f = File(s.db.path + suffix)
            if (exists(f)) Files.move(f.toPath(), File(aside, f.name).toPath())
        }
        FileOutputStream(s.db).use { it.write(snapshot) }
        return s.data.list()!!.toSet()
    }

    /** A server folder with a database grown by [rows] rows, a running server on it, its first snapshot and five saves after. */
    private fun ranAndSavedAfter(rows: Int): Pair<Server, Started> {
        val s = server()
        if (rows > 0) grow(s.db, rows)
        val started = startServer(s)
        assertTrue(started.process.isAlive, "the server runs: ${started.lines()}")
        assertWorked(run(s), "the first night")
        connect(s.db).use { c -> for (i in 1..5) c.exec("INSERT INTO meta(key,value) VALUES(?,?)", "after the snapshot $i", "1") }
        s.at(BackupFixture.NIGHT_2)
        return s to started
    }

    /** No name was given tonight, the nightly name is still the first snapshot, and nothing is left under the temporary names. */
    private fun assertNoNameGiven(s: Server, nightly: ByteArray, what: String) {
        assertFalse(exists(s.dated(BackupFixture.NIGHT_2)), "$what: no dated name tonight")
        assertTrue(s.nightly.readBytes().contentEquals(nightly), "$what: the nightly name is still the first snapshot")
        for (name in ServerBackup.TEMPORARY_FAMILY) assertFalse(exists(File(s.backup, name)), "$what: $name is not left")
    }

    // ---------------------------------------------------------------------------------------------------------------
    // The race: a server that stops while a run works, and the operator's restore
    // ---------------------------------------------------------------------------------------------------------------

    /**
     * The command as a process of its own, stopped by the real SIGSTOP once `/proc/<pid>/fd` shows the database and its
     * `-wal` open (in the middle of its read of a database of about 20 MB); the server then ends by the real SIGTERM, the
     * operator restores by the guide's steps, and the command goes on (SIGCONT). The put-back database is byte for byte the
     * snapshot, no name was given, and the run printed one line and ended with status 1.
     */
    @Test
    fun theRace_aRunStoppedInItsRead_whileTheServerStopsAndTheOperatorRestores_changesNothing_andNamesNothing() {
        val (s, server) = ranAndSavedAfter(10_000)
        val snapshot = s.nightly.readBytes()
        val dir = newFolder("race-process")
        val out = File(dir, "out")
        val err = File(dir, "err")
        val pb = ProcessBuilder(
            File(System.getProperty("java.home"), "bin/java").path, "-Djava.io.tmpdir=" + System.getProperty("java.io.tmpdir"),
            "-cp", System.getProperty("java.class.path"), "io.silencelen.andvari.server.MainKt", "admin", "backup", "--env-file", s.env.path,
        ).redirectOutput(out).redirectError(err).redirectInput(ProcessBuilder.Redirect.from(File("/dev/null")))
        pb.environment().keys.removeIf { it.startsWith("ANDVARI_") }
        val cmd = pb.start()
        try {
            val pid = cmd.pid()
            val end = System.nanoTime() + TimeUnit.MINUTES.toNanos(1)
            var caught = false
            while (System.nanoTime() < end && cmd.isAlive) {
                val open = fds(pid)
                if (open.any { it == s.db.path } && open.any { it == s.db.path + "-wal" }) {
                    signal("STOP", pid)
                    caught = true
                    break
                }
            }
            assertTrue(caught, "the run was stopped with the database open: ${err.readText()}")
            val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5)
            while (stateOf(pid) !in setOf("T", "t") && System.nanoTime() < deadline) Thread.sleep(2)
            record("process race: stopped with ${fds(pid).filter { it.contains(s.data.path) }}")
            assertEquals(143, server.term(), "the real SIGTERM")
            val afterSteps = restore(s, snapshot)
            signal("CONT", pid)
            assertTrue(cmd.waitFor(3, TimeUnit.MINUTES), "the run ends")
            val line = err.readText()
            record("process race: status ${cmd.exitValue()}, line <${line.trimEnd()}>")
            assertEquals(1, cmd.exitValue(), "status 1: $line")
            assertEquals("", out.readText())
            assertTrue(line.startsWith("andvari: backup stopped at ") && line.endsWith("\n") && line.count { it == '\n' } == 1, "one line: $line")
            assertTrue(s.db.readBytes().contentEquals(snapshot), "the put-back database is byte for byte the snapshot (${s.db.length()} bytes, the snapshot ${snapshot.size})")
            assertNoNameGiven(s, snapshot, "process race")
            record("process race: new in the data folder after the run: ${s.data.list()!!.toSet() - afterSteps}" +
                " (${(s.data.list()!!.toSet() - afterSteps).joinToString { "$it ${File(s.data, it).length()} bytes" }})")
            recordRestoredAndStart(s, "process race")
        } finally {
            if (cmd.isAlive) cmd.destroyForcibly().waitFor()
        }
    }

    /**
     * The command in this process, held by its hook at the step after the start's decision, once the database and its
     * `-wal` are open on its connection; the server in a process of its own ends by the real SIGTERM, the operator
     * restores by the guide's steps, and the run goes on: the put-back database is byte for byte the snapshot, no name was
     * given, and the run ends with one line.
     */
    @Test
    fun theRace_aRunHeldOnceTheWriteAheadFileIsOpen_whileTheServerStopsAndTheOperatorRestores_changesNothing_andNamesNothing() {
        val (s, server) = ranAndSavedAfter(0)
        val snapshot = s.nightly.readBytes()
        var afterSteps: Set<String>? = null
        var openAtTheStop: List<String> = emptyList()
        val line = try {
            BackupFixture.backup(
                s,
                seams = ServerBackup.Seams(
                    atStep = { step ->
                        if (step == ServerBackup.Step.FOLDER && afterSteps == null) {
                            openAtTheStop = fds(ProcessHandle.current().pid()).filter { it.startsWith(s.db.path) }
                            assertEquals(143, server.term(), "the real SIGTERM")
                            afterSteps = restore(s, snapshot)
                        }
                    },
                ),
            )
        } finally {
            if (server.process.isAlive) server.kill()
        }
        record("held race: open at the stop $openAtTheStop; the line <$line>")
        assertTrue(openAtTheStop.contains(s.db.path) && openAtTheStop.contains(s.db.path + "-wal"), "held with the database and its -wal open: $openAtTheStop")
        assertNotNull(line, "the run is refused")
        assertFalse(line.contains("\n"), "one line: $line")
        assertTrue(s.db.readBytes().contentEquals(snapshot), "the put-back database is byte for byte the snapshot (${s.db.length()} bytes, the snapshot ${snapshot.size})")
        assertNoNameGiven(s, snapshot, "held race")
        val made = s.data.list()!!.toSet() - afterSteps!!
        record("held race: new in the data folder after the run: $made (${made.joinToString { "$it ${File(s.data, it).length()} bytes" }})")
        recordRestoredAndStart(s, "held race")
    }

    /**
     * The command in this process, held by its hook once its connection to the database is open and before its first
     * read (the database file open, its `-wal` not yet); the server in a process of its own ends by the real SIGTERM, the
     * operator restores by the guide's steps, and the run goes on: it reads the put-back file and makes and checks its
     * snapshot, and the second look finds no holder. The put-back database is byte for byte the snapshot, no name was
     * given, and the run ends with the second look's line.
     */
    @Test
    fun theRace_aRunHeldOnceTheDatabaseIsOpenBeforeItsFirstRead_whileTheServerStopsAndTheOperatorRestores_namesNothing() {
        val (s, server) = ranAndSavedAfter(0)
        val snapshot = s.nightly.readBytes()
        var afterSteps: Set<String>? = null
        var openAtTheStop: List<String> = emptyList()
        val line = try {
            BackupFixture.backup(
                s,
                seams = ServerBackup.Seams(
                    opened = {
                        openAtTheStop = fds(ProcessHandle.current().pid()).filter { it.startsWith(s.db.path) }
                        assertEquals(143, server.term(), "the real SIGTERM")
                        afterSteps = restore(s, snapshot)
                    },
                ),
            )
        } finally {
            if (server.process.isAlive) server.kill()
        }
        record("opened race: open at the stop $openAtTheStop; the line <$line>")
        assertTrue(openAtTheStop.contains(s.db.path), "held with the database open: $openAtTheStop")
        assertEquals(again(s, "nothing holds the lock on ${s.serverLock.path}"), line, "the line")
        assertTrue(s.db.readBytes().contentEquals(snapshot), "the put-back database is byte for byte the snapshot (${s.db.length()} bytes, the snapshot ${snapshot.size})")
        assertNoNameGiven(s, snapshot, "opened race")
        val made = s.data.list()!!.toSet() - afterSteps!!
        record("opened race: new in the data folder after the run: $made (${made.joinToString { "$it ${File(s.data, it).length()} bytes" }})")
        recordRestoredAndStart(s, "opened race")
    }

    /**
     * A stop, a restore and a new start within one run: the command in this process is held by its hook at the check of
     * the snapshot (made from the first server's database, its connection closed); the server ends by the real SIGTERM,
     * the operator restores the first snapshot by the guide's steps and runs `restored`, and a new server starts on it in a
     * process of its own. The second look finds the lock held by another start: the snapshot is not kept.
     */
    @Test
    fun aStopARestoreAndANewStartWithinOneRun_theSnapshotIsNotKept() {
        val (s, server) = ranAndSavedAfter(0)
        val snapshot = s.nightly.readBytes()
        var afterSteps: Set<String>? = null
        var second: Started? = null
        try {
            val line = BackupFixture.backup(
                s,
                seams = ServerBackup.Seams(
                    atStep = { step ->
                        if (step == ServerBackup.Step.CHECK && second == null) {
                            assertEquals(143, server.term(), "the real SIGTERM")
                            afterSteps = restore(s, snapshot)
                            assertEquals(null, BackupFixture.restoredRefusal(s), "restored")
                            second = startServer(s)
                            assertTrue(second!!.process.isAlive && lockWarnings(second!!).isEmpty(), "the new start holds the lock: ${second!!.lines()}")
                        }
                    },
                ),
            )
            record("stop, restore, start within one run: <$line>")
            assertEquals(again(s, anotherLine(s)), line, "the line")
            assertNoNameGiven(s, snapshot, "a new start within the run")
            val made = s.data.list()!!.toSet() - afterSteps!!
            record("stop, restore, start: new in the data folder after the run, the new server running: $made")
        } finally {
            if (server.process.isAlive) server.kill()
            second?.let { if (it.process.isAlive) it.term() }
        }
        recordRestoredAndStart(s, "stop, restore, start")
    }

    // ---------------------------------------------------------------------------------------------------------------
    // A snapshot or a check that fails: one look more before the line
    // ---------------------------------------------------------------------------------------------------------------

    /** What SQLite says of a database whose damaged page a read reaches, as the line quotes it. */
    private val malformed = "[SQLITE_CORRUPT] The database disk image is malformed (database disk image is malformed)"

    /** The line of a run whose snapshot failed with SQLite's words [sqlite] and [clause] before its end, without "andvari: ". */
    private fun snapshotFailed(s: Server, sqlite: String, clause: String = "") =
        "backup stopped at the snapshot: the snapshot into ${s.temporary.path} failed ($sqlite); ${clause}no earlier snapshot was changed"

    /** The clause of a failed snapshot or check where the look finds the lock no longer held as it was ([found]). */
    private fun noLongerHeld(s: Server, found: String) =
        "the lock on ${s.serverLock.path} is no longer held as it was when this run began ($found), so the database's files may " +
            "have been moved or replaced while this run read them, and this failure says nothing certain about the database " +
            "that is there now; "

    /** The clause of a failed snapshot or check where the look cannot tell ([found]). */
    private fun cannotTellStill(s: Server, found: String) =
        "this command cannot tell whether the lock on ${s.serverLock.path} is still held as it was when this run began ($found), " +
            "so the database's files may have been moved or replaced while this run read them, and this failure says nothing " +
            "certain about the database that is there now; "

    /**
     * A server folder whose database has real damage: [rows] grown rows, all of them in the database file itself (no
     * write-ahead file is left), then the page of the file that holds the row in their middle written over with zeros.
     * The first page and the schema stay whole, so a server starts on it; a read of every row, as the snapshot makes it,
     * reaches the damaged page.
     */
    private fun damaged(rows: Int = 2_000): Server {
        val s = server()
        grow(s.db, rows)
        assertFalse(File(s.db.path + "-wal").let { exists(it) && it.length() > 0 }, "the grown rows are in the database file")
        val bytes = s.db.readBytes()
        val size = (((bytes[16].toInt() and 0xff) shl 8) or (bytes[17].toInt() and 0xff)).let { if (it == 1) 65_536 else it }
        val marker = "g${rows / 2}x".encodeToByteArray()
        val at = (0..bytes.size - marker.size).first { i -> marker.indices.all { bytes[i + it] == marker[it] } }
        val page = at / size
        assertTrue(page > 0, "the damaged page is not the first")
        RandomAccessFile(s.db, "rw").use { f ->
            f.seek(page.toLong() * size)
            f.write(ByteArray(size))
        }
        return s
    }

    /**
     * T1. Real damage beside a real running server that still holds the database when the run fails: the command, a
     * process of its own, prints SQLite's words in the plain line, word for word, with nothing added, and the server runs on.
     */
    @Test
    fun aSnapshotThatFailsOnRealDamage_besideTheServerThatStillHoldsIt_printsThePlainLine() {
        val s = damaged()
        withServer(startServer(s)) { st ->
            assertTrue(st.process.isAlive && st.lines().any { it.contains(BackupFixture.LISTENING) }, "the server starts on it: ${st.lines()}")
            val r = run(s)
            record("real damage beside a running server: status ${r.code}, line <${r.err.trimEnd()}>")
            assertRefused(r, "andvari: ${snapshotFailed(s, malformed)}\n", "real damage, the server still running")
            assertTrue(st.process.isAlive, "the server runs on")
        }
    }

    /**
     * T2. The same damage; the command in this process is held by its hook at the entry of the step of the snapshot, and
     * there the real server ends by the real SIGTERM (nothing is exchanged). The snapshot fails on the damage, and the line
     * says that the lock is no longer held as it was, before its end.
     */
    @Test
    fun aSnapshotThatFailsOnRealDamage_afterTheServerEndedWithinTheRun_saysTheLockIsNoLongerHeldAsItWas() {
        val s = damaged()
        val server = startServer(s)
        var ended = false
        val line = try {
            assertTrue(server.process.isAlive, "the server starts on it: ${server.lines()}")
            BackupFixture.backup(
                s,
                seams = ServerBackup.Seams(
                    atStep = { step ->
                        if (step == ServerBackup.Step.SNAPSHOT && !ended) {
                            assertEquals(143, server.term(), "the real SIGTERM")
                            ended = true
                        }
                    },
                ),
            )
        } finally {
            if (server.process.isAlive) server.kill()
        }
        record("real damage, the server ended within the run: <$line>")
        assertTrue(ended, "the server ended at the step of the snapshot")
        assertEquals(snapshotFailed(s, malformed, noLongerHeld(s, "nothing holds the lock on ${s.serverLock.path}")), line, "the line")
    }

    /**
     * T4. The same damage; at the entry of the step of the snapshot the real server is killed by the real SIGKILL and a
     * helper process of this test takes the first part of the lock only. The snapshot fails on the damage, and the line
     * says that the command cannot tell whether the lock is still held as it was, before its end.
     */
    @Test
    fun aSnapshotThatFailsOnRealDamage_whileAPartOfTheLockIsHeldAndTheSecondIsNot_saysItCannotTell() {
        val s = damaged()
        val server = startServer(s)
        var first: Process? = null
        val line = try {
            assertTrue(server.process.isAlive, "the server starts on it: ${server.lines()}")
            BackupFixture.backup(
                s,
                seams = ServerBackup.Seams(
                    atStep = { step ->
                        if (step == ServerBackup.Step.SNAPSHOT && first == null) {
                            assertEquals(137, server.kill(), "the real SIGKILL")
                            first = holder(s.serverLock, "first")
                        }
                    },
                ),
            )
        } finally {
            if (server.process.isAlive) server.kill()
            first?.destroyForcibly()?.waitFor()
        }
        record("real damage, a part of the lock held at the snapshot: <$line>")
        assertNotNull(first, "the helper took the first part at the step of the snapshot")
        assertEquals(snapshotFailed(s, malformed, cannotTellStill(s, firstPartOnly(s))), line, "the line")
    }

    /** The words of the error the seam of the look throws in the tests of a later look that fails. */
    private val lookError = "the disk refused the read of the lock file"

    /** What a later look that failed found, as the line says it. */
    private fun lookFailed(s: Server) = "the look at ${s.serverLock.path} failed ($lookError)"

    /** The seam of the look: the first look passes, the [nth] look throws an I/O error; [calls] counts the looks. */
    private fun failingLook(nth: Int, calls: IntArray) = ServerBackup.Seams(
        looking = {
            calls[0]++
            if (calls[0] == nth) throw IOException(lookError)
        },
    )

    /**
     * T5. The damage of T1, beside a real running server that still holds the lock; the command in this process, whose
     * look throws an I/O error at the look before the failed snapshot's line (its first look passes). The line holds the
     * failure's own words first, and says that the command cannot tell whether the lock is still held as it was. The
     * database keeps every byte, no snapshot name is given, and the temporary file is gone.
     */
    @Test
    fun aLookThatFailsBeforeAFailedSnapshotsLine_keepsTheFailuresWords_andSaysItCannotTell() {
        val s = damaged()
        withServer(startServer(s)) { st ->
            assertTrue(st.process.isAlive && st.lines().any { it.contains(BackupFixture.LISTENING) }, "the server starts on it: ${st.lines()}")
            val db = s.db.readBytes()
            val calls = IntArray(1)
            val line = BackupFixture.backup(s, seams = failingLook(2, calls))
            record("a later look that fails, after a failed snapshot: <$line>")
            assertEquals(2, calls[0], "two looks: the first passed, the second failed")
            assertEquals(snapshotFailed(s, malformed, cannotTellStill(s, lookFailed(s))), line, "the one line (status 1)")
            assertTrue(s.db.readBytes().contentEquals(db), "the database keeps every byte")
            assertFalse(exists(s.nightly), "no nightly name")
            assertEquals(emptyList(), s.backup.list()!!.filter { ServerBackup.DATED.matches(it) }, "no dated name")
            for (name in ServerBackup.TEMPORARY_FAMILY) assertFalse(exists(File(s.backup, name)), "$name is not left")
            assertTrue(st.process.isAlive, "the server runs on")
        }
    }

    /**
     * T6. No damage, beside a real running server that still holds the lock; the command in this process, whose look
     * throws an I/O error at the second look, once the snapshot is made and checked (its first look passes). The second
     * look's line says that the command cannot tell whether the lock is still held as it was; no name is given tonight,
     * the nightly name is still the earlier snapshot, and the temporary file is gone.
     */
    @Test
    fun aSecondLookThatFails_saysItCannotTell_andNamesNothing() {
        val s = server()
        withServer(startServer(s)) { st ->
            assertTrue(st.process.isAlive && st.lines().any { it.contains(BackupFixture.LISTENING) }, "the server starts: ${st.lines()}")
            assertWorked(run(s), "the first night")
            val nightly = s.nightly.readBytes()
            s.at(BackupFixture.NIGHT_2)
            val calls = IntArray(1)
            val line = BackupFixture.backup(s, seams = failingLook(2, calls))
            record("a second look that fails: <$line>")
            assertEquals(2, calls[0], "two looks: the first passed, the second failed")
            assertEquals(
                "backup stopped at the server, looked at again: the snapshot was made and checked, but this command cannot tell " +
                    "whether the lock on ${s.serverLock.path} is still held as it was when this run began (${lookFailed(s)}); " +
                    "tonight's snapshot was not kept, and no earlier snapshot was changed",
                line,
                "the one line (status 1)",
            )
            assertNoNameGiven(s, nightly, "a second look that fails")
            assertTrue(st.process.isAlive, "the server runs on")
        }
    }

    /**
     * The race held at the snapshot: a database grown by [rows] rows, a running server, its first snapshot and five saves
     * after; the command in this process, held by its hook at the entry of the step of the snapshot (its connection open,
     * the start's decision read through the server's write-ahead file); there the real server ends by the real SIGTERM and
     * the operator restores the first snapshot by the guide's steps, and the run goes on. The server folder, the snapshot
     * put back, and the run's line.
     */
    private fun raceHeldAtTheSnapshot(rows: Int): Triple<Server, ByteArray, String?> {
        val (s, server) = ranAndSavedAfter(rows)
        val snapshot = s.nightly.readBytes()
        var restored = false
        val line = try {
            BackupFixture.backup(
                s,
                seams = ServerBackup.Seams(
                    atStep = { step ->
                        if (step == ServerBackup.Step.SNAPSHOT && !restored) {
                            assertEquals(143, server.term(), "the real SIGTERM")
                            restore(s, snapshot)
                            restored = true
                        }
                    },
                ),
            )
        } finally {
            if (server.process.isAlive) server.kill()
        }
        assertTrue(restored, "the server ended and the operator restored at the step of the snapshot")
        return Triple(s, snapshot, line)
    }

    /**
     * T3. The exchange itself, nothing damaged by hand ([raceHeldAtTheSnapshot], a database grown by 2 000 rows): the run's
     * snapshot reads the put-back file through the write-ahead file and index it had open, and SQLite finds that mixture
     * malformed. The line says that the lock is no longer held as it was, word for word; the put-back database is byte for
     * byte the snapshot, and no name was given.
     */
    @Test
    fun theRace_aRunHeldAtTheSnapshot_whileTheServerStopsAndTheOperatorRestores_saysTheLockIsNoLongerHeldAsItWas() {
        val (s, snapshot, line) = raceHeldAtTheSnapshot(2_000)
        record("race held at the snapshot: <$line>")
        assertEquals(snapshotFailed(s, malformed, noLongerHeld(s, "nothing holds the lock on ${s.serverLock.path}")), line, "the line")
        assertTrue(s.db.readBytes().contentEquals(snapshot), "the put-back database is byte for byte the snapshot (${s.db.length()} bytes, the snapshot ${snapshot.size})")
        assertNoNameGiven(s, snapshot, "race held at the snapshot")
    }

    // ---------------------------------------------------------------------------------------------------------------
    // The line names the database
    // ---------------------------------------------------------------------------------------------------------------

    /** A stopped server's folder: its database with the `-wal` and `-shm` it left, and its unlocked `server.lock`. */
    private fun stoppedWithWriteAhead(): Server {
        val s = server()
        withServer(startServer(s)) { st ->
            connect(s.db).use { it.exec("INSERT INTO meta(key,value) VALUES('saved while it ran','1')") }
            assertEquals(143, st.term())
        }
        assertTrue(exists(File(s.db.path + "-wal")) && exists(File(s.db.path + "-shm")))
        return s
    }

    /**
     * The settings name another database in the same data folder (`b.db`, a stopped server's database with its `-wal` and
     * `-shm`) while the server runs on `andvari.db`: refused at the server; `b.db` and its files keep every byte, and
     * nothing is made.
     */
    @Test
    fun settingsThatNameAnotherDatabaseInTheDataFolder_areRefused_andThatDatabaseKeepsEveryByte() {
        val s = server()
        withServer(startServer(s)) { st ->
            val stopped = stoppedWithWriteAhead()
            val b = File(s.data, "b.db")
            for (suffix in listOf("", "-wal", "-shm")) Files.copy(File(stopped.db.path + suffix).toPath(), File(b.path + suffix).toPath())
            HostCli.editEnvFile(s.env, mapOf("ANDVARI_DB" to b.path))
            val before = besideARunningServer(s)
            assertRefused(run(s), other(s, b.path), "another database in the folder")
            assertEquals(before, besideARunningServer(s), "b.db, its -wal and -shm keep every byte; nothing is made")
            assertFalse(exists(s.backup), "no backup folder")
            assertTrue(st.process.isAlive)
        }
    }

    /**
     * `server.lock` of a stopped server's folder is a second name of the lock file of a server that runs on another folder:
     * the lock is held, and its line names that server's database. Refused; nothing changes in the stopped folder.
     */
    @Test
    fun aLockFileThatIsASecondNameOfAnotherServersLockFile_isRefused_andNothingChanges() {
        val a = server()
        withServer(startServer(a)) { _ ->
            val s = stoppedWithWriteAhead()
            Files.move(s.serverLock.toPath(), File(newFolder("moved-out"), ServerLock.NAME).toPath())
            Files.createLink(s.serverLock.toPath(), a.serverLock.toPath())
            val before = tree(s.data)
            assertRefused(run(s), other(s, s.db.path), "a second name of another server's lock file")
            assertEquals(before, tree(s.data), "nothing changes")
        }
    }

    /**
     * `server.lock` of a stopped server's folder is a second name of a file that a process of its own holds the lock on,
     * and that holds no line: refused; nothing changes.
     */
    @Test
    fun aLockFileThatIsASecondNameOfAFileAnotherProcessHolds_isRefused_andNothingChanges() {
        val s = stoppedWithWriteAhead()
        val held = File(newFolder("held"), "held")
        Files.createFile(held.toPath())
        val pb = ProcessBuilder(
            File(System.getProperty("java.home"), "bin/java").path, "-cp", System.getProperty("java.class.path"), HolderOfALock::class.java.name, held.path,
        ).redirectErrorStream(true).redirectInput(ProcessBuilder.Redirect.from(File("/dev/null")))
        val holder = pb.start()
        try {
            assertEquals(HolderOfALock.HOLDING, holder.inputStream.bufferedReader().readLine())
            Files.move(s.serverLock.toPath(), File(newFolder("moved-out"), ServerLock.NAME).toPath())
            Files.createLink(s.serverLock.toPath(), held.toPath())
            val before = tree(s.data)
            assertRefused(run(s), noLine(s), "a second name of a held file")
            assertEquals(before, tree(s.data), "nothing changes")
        } finally {
            holder.destroyForcibly().waitFor()
        }
    }

    /** A line that names no database (written over by hand) under a running server: refused; nothing changes. */
    @Test
    fun aDamagedLineUnderARunningServer_isRefused_andNothingChanges() {
        val s = server()
        withServer(startServer(s)) { st ->
            s.serverLock.writeText("server 12\n")
            val before = besideARunningServer(s)
            assertRefused(run(s), noLine(s), "a damaged line")
            assertEquals(before, besideARunningServer(s))
            assertTrue(st.process.isAlive)
        }
    }

    /** The settings name a database file that is not there, while the server runs on `andvari.db`: refused; nothing is made. */
    @Test
    fun settingsThatNameADatabaseFileThatIsNotThere_areRefusedAtTheServer() {
        val s = server()
        withServer(startServer(s)) { _ ->
            val gone = File(s.data, "not-there.db")
            HostCli.editEnvFile(s.env, mapOf("ANDVARI_DB" to gone.path))
            val before = besideARunningServer(s)
            assertRefused(run(s), cannotRead(s, gone.path, "there is no such file"), "no such database file")
            assertEquals(before, besideARunningServer(s))
            assertFalse(exists(gone))
        }
    }

    // ---------------------------------------------------------------------------------------------------------------
    // The read-only open, without the look
    // ---------------------------------------------------------------------------------------------------------------

    /**
     * With the looks taken out by the seam (this process; no server), a run over a stopped server's database with its
     * `-wal` beside it: the database keeps every byte, and its `-wal` stays.
     */
    @Test
    fun withTheLooksTakenOut_aRunOverAStoppedServersDatabase_leavesItByteForByte_andItsWriteAheadFileStays() {
        val s = stoppedWithWriteAhead()
        val db = s.db.readBytes()
        val wal = File(s.db.path + "-wal")
        val walBytes = wal.readBytes()
        val line = BackupFixture.backup(s)
        record("the read-only open without the look: <$line>")
        assertTrue(s.db.readBytes().contentEquals(db), "the database keeps every byte")
        assertTrue(exists(wal) && wal.readBytes().contentEquals(walBytes), "its -wal stays, byte for byte")
    }

    // ---------------------------------------------------------------------------------------------------------------
    // The lock file under a running server; the server's line
    // ---------------------------------------------------------------------------------------------------------------

    /** `server.lock` replaced by a new file of that name while the server runs: the line word for word, nothing changes. */
    @Test
    fun theLockFileReplacedByANewFileUnderARunningServer_isRefusedWithTheLine() {
        val s = server()
        withServer(startServer(s)) { st ->
            assertWorked(run(s), "before the file was replaced")
            Files.move(s.serverLock.toPath(), File(newFolder("moved-out"), ServerLock.NAME).toPath())
            Files.createFile(s.serverLock.toPath())
            val before = besideARunningServer(s)
            assertRefused(run(s), noHolder(s), "the file replaced")
            assertEquals(before, besideARunningServer(s))
            assertTrue(st.process.isAlive)
        }
    }

    /**
     * The server's line: once it holds the lock, `server.lock` holds one line, which names its database file; a second
     * server on the folder (which never holds the lock) writes nothing into it; a run works after the start, so the line
     * was written without letting go of the lock. Each start writes a value of its own.
     */
    @Test
    fun theServersLine_oneLineAfterTheStart_aSecondServerWritesNothing_andARunWorks() {
        val s = server()
        val firstLine = withServer(startServer(s)) { first ->
            assertEquals(emptyList(), lockWarnings(first), "the server took the lock")
            val line = s.serverLock.readText()
            assertTrue(LINE.matches(line), "one line: <$line>")
            val key = Files.readAttributes(s.db.toPath(), java.nio.file.attribute.BasicFileAttributes::class.java).fileKey().toString()
            assertTrue(line.endsWith(" database $key\n"), "it names the database file $key: <$line>")
            record("the server's line: <${line.trimEnd()}>")
            withServer(startServer(s)) { second ->
                assertEquals(1, lockWarnings(second).size, "the second server did not take the lock: ${second.lines()}")
                assertEquals(line, s.serverLock.readText(), "the second server wrote nothing into the file")
                assertWorked(run(s), "while both run")
            }
            s.at(BackupFixture.NIGHT_2)
            assertWorked(run(s), "after the start")
            assertEquals(143, first.term())
            line
        }
        withServer(startServer(s)) { _ ->
            val next = s.serverLock.readText()
            assertTrue(LINE.matches(next) && next != firstLine, "the next start writes a value of its own: <$next>, <$firstLine>")
        }
    }

    /** A server whose database is not a file (`ANDVARI_DB=:memory:`): no lock file is made, and nothing is printed of it. */
    @Test
    fun aServerWhoseDatabaseIsNotAFile_takesNoLock_andSaysNothingOfIt() {
        val s = server()
        HostCli.editEnvFile(s.env, mapOf("ANDVARI_DB" to ":memory:"))
        val cwd = newFolder("memory-cwd")
        withServer(startServer(s, dir = cwd)) { st ->
            assertTrue(st.process.isAlive && st.lines().any { it.contains(BackupFixture.LISTENING) }, "it starts: ${st.lines()}")
            assertEquals(emptyList(), st.lines().filter { it.contains("the lock") }, "nothing about the lock")
            assertEquals(emptyList(), cwd.list()!!.toList(), "no file in its working folder")
            assertFalse(exists(s.serverLock))
        }
    }

    /**
     * The lock comes after the database is open and caught up: a database that must be caught up at the start (one index
     * of the baseline dropped from a table of 300 000 rows, so that building it again takes a while). Runs of the command
     * (its own code in this process) one after another from the start's first line until it listens: every snapshot one
     * of them makes holds what the catch-up made, and at least one of them looked while the server had its database open
     * and found no holder. Once the server listens, a run works and its snapshot holds the index.
     */
    @Test
    fun theLockComesAfterTheDatabaseIsCaughtUp_aLookDuringTheStartFindsNoHolder() {
        val s = server()
        val index = "idx_audit_type_at"
        connect(s.db).use { c ->
            c.autoCommit = false
            c.prepareStatement("INSERT INTO audit(at,type,userId) VALUES(?,?,?)").use { st ->
                for (i in 1..300_000) {
                    st.setLong(1, i.toLong())
                    st.setString(2, "type ${i % 97}")
                    st.setString(3, "user ${i % 1013}")
                    st.addBatch()
                    if (i % 5_000 == 0) st.executeBatch()
                }
                st.executeBatch()
            }
            c.commit()
            c.autoCommit = true
            c.exec("DROP INDEX $index")
        }
        val withoutTheIndex = ArrayList<Long>()
        var taken = 0
        val runs = ArrayList<String>()
        var refusedWhileItsDatabaseWasOpen = 0
        val seams = ServerBackup.Seams(
            atStep = { step ->
                if (step == ServerBackup.Step.CHECK) {
                    taken++
                    val n = connect(BackupFixture.copyAside(s.temporary)).use { c -> c.count("SELECT COUNT(*) FROM sqlite_master WHERE name=?", index) }
                    if (n == 0L) withoutTheIndex += System.nanoTime()
                }
            },
        )
        val started = startServer(s, "ANDVARI_SET_BY_THE_HOLDER_TEST" to "1", until = "env WARNING")
        try {
            val pid = started.process.pid()
            val end = System.nanoTime() + TimeUnit.MINUTES.toNanos(1)
            while (System.nanoTime() < end && started.process.isAlive && started.lines().none { it.contains(BackupFixture.LISTENING) }) {
                val open = fds(pid).any { it == s.db.path }
                val line = BackupFixture.backup(s, seams = seams)
                if (open && line != null && line.startsWith("backup stopped at the server: ")) refusedWhileItsDatabaseWasOpen++
                if (runs.lastOrNull() != line.toString()) runs += line.toString()
            }
            record("runs during the start (each different line once): $runs; snapshots made $taken; looks refused while its database was open: $refusedWhileItsDatabaseWasOpen")
            assertTrue(started.waitFor(BackupFixture.LISTENING), "the server starts: ${started.lines()}")
            assertTrue(started.lines().any { it.contains("brought up to baseline") && it.contains(index) }, "the start caught up: ${started.lines()}")
            assertEquals(emptyList(), lockWarnings(started))
            assertEquals(emptyList(), withoutTheIndex, "no snapshot made during the start lacks what the catch-up made")
            assertTrue(refusedWhileItsDatabaseWasOpen > 0, "a look came while the server had its database open: $runs")
            s.at(BackupFixture.NIGHT_2)
            assertWorked(run(s), "a run once the start is done")
            val inSnapshot = connect(BackupFixture.copyAside(s.nightly)).use { c -> c.count("SELECT COUNT(*) FROM sqlite_master WHERE name=?", index) }
            assertEquals(1L, inSnapshot, "the snapshot holds the index the catch-up made")
        } finally {
            if (started.process.isAlive) started.kill()
        }
    }

    // ---------------------------------------------------------------------------------------------------------------
    // The two parts of the lock, and the file the server names
    // ---------------------------------------------------------------------------------------------------------------

    /** What a look finds where the first part of the lock is held and the second is not. */
    private fun firstPartOnly(s: Server) = "a part of the lock on ${s.serverLock.path} was held when this command looked, and not the second part"

    /** The server's lock warning with its reason [why], as the start prints it. */
    private fun warning(s: Server, why: String) =
        "[andvari] WARNING: the server could not take the lock on ${s.serverLock.path} ($why) and starts without it. " +
            "`andvari admin backup` takes a snapshot only while a process holds the lock on that file."

    /** A helper process of these tests ([main] and its arguments), from this test's own classes and libraries. */
    private fun helper(main: String, vararg args: String): Process =
        ProcessBuilder(listOf(File(System.getProperty("java.home"), "bin/java").path, "-cp", System.getProperty("java.class.path"), main) + args)
            .redirectErrorStream(true).redirectInput(ProcessBuilder.Redirect.from(File("/dev/null"))).start()

    /** [HolderOfALock] on [f] with [mode] ("first", "second" or both parts), returned once it holds what it takes. */
    private fun holder(f: File, mode: String? = null): Process =
        helper(HolderOfALock::class.java.name, *listOfNotNull(f.path, mode).toTypedArray()).also {
            assertEquals(HolderOfALock.HOLDING, it.inputStream.bufferedReader().readLine())
        }

    /** What [ProbeOfALock], a process of its own, finds on [f] ([mode]: "shared" or "exclusive"). */
    private fun probe(f: File, mode: String): String {
        val p = helper(ProbeOfALock::class.java.name, f.path, mode)
        val said = p.inputStream.bufferedReader().readText().trim()
        assertTrue(p.waitFor(1, TimeUnit.MINUTES) && p.exitValue() == 0, "the probe ends: $said")
        return said
    }

    /**
     * (a) A look while a process holds the first part of the lock only, and the file still holds the line of a real
     * server that was then killed by the real SIGKILL. The holder is a helper process of this test: it stands in for a
     * server between its first part and its second part. The command, a process of its own: the line word for word,
     * status 1; nothing in the data folder changes, and no backup folder is made.
     */
    @Test
    fun aLookWhileOnlyTheFirstPartIsHeld_overAKilledServersLine_cannotTell_andChangesNothing() {
        val s = server()
        withServer(startServer(s)) { st -> assertEquals(137, st.kill(), "the real SIGKILL") }
        assertTrue(LINE.matches(s.serverLock.readText()), "the killed server's line is in the file")
        val first = holder(s.serverLock, "first")
        try {
            val before = tree(s.data)
            assertRefused(run(s), "andvari: backup stopped at the server: ${firstPartOnly(s)}, $cannotTell\n", "the first part only")
            assertEquals(before, tree(s.data), "nothing changes")
            assertFalse(exists(s.backup), "no backup folder")
        } finally {
            first.destroyForcibly().waitFor()
        }
    }

    /**
     * (b) The instant of a start, from end to end: a real server; the command, a process of its own, passes its first look
     * and is stopped by the real SIGSTOP once its database and `-wal` are open (a database of about 20 MB); the server ends
     * by the real SIGTERM; a helper process takes the first part of the lock (it stands in for a new server between its
     * first part and its line, the stopped server's line still in the file); the command goes on (SIGCONT). Its second look
     * refuses: no name was given, and the temporary snapshot is gone.
     */
    @Test
    fun aStopAndANewStartsFirstPartWithinOneRun_theSecondLookCannotTell_andNamesNothing() {
        val (s, server) = ranAndSavedAfter(10_000)
        val snapshot = s.nightly.readBytes()
        val dir = newFolder("first-part-race")
        val out = File(dir, "out")
        val err = File(dir, "err")
        val pb = ProcessBuilder(
            File(System.getProperty("java.home"), "bin/java").path, "-Djava.io.tmpdir=" + System.getProperty("java.io.tmpdir"),
            "-cp", System.getProperty("java.class.path"), "io.silencelen.andvari.server.MainKt", "admin", "backup", "--env-file", s.env.path,
        ).redirectOutput(out).redirectError(err).redirectInput(ProcessBuilder.Redirect.from(File("/dev/null")))
        pb.environment().keys.removeIf { it.startsWith("ANDVARI_") }
        val cmd = pb.start()
        var first: Process? = null
        try {
            val pid = cmd.pid()
            val end = System.nanoTime() + TimeUnit.MINUTES.toNanos(1)
            var caught = false
            while (System.nanoTime() < end && cmd.isAlive) {
                val open = fds(pid)
                if (open.any { it == s.db.path } && open.any { it == s.db.path + "-wal" }) {
                    signal("STOP", pid)
                    caught = true
                    break
                }
            }
            assertTrue(caught, "the run was stopped with the database open: ${err.readText()}")
            val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5)
            while (stateOf(pid) !in setOf("T", "t") && System.nanoTime() < deadline) Thread.sleep(2)
            assertEquals(143, server.term(), "the real SIGTERM")
            assertTrue(LINE.matches(s.serverLock.readText()), "the stopped server's line is still in the file")
            first = holder(s.serverLock, "first")
            signal("CONT", pid)
            assertTrue(cmd.waitFor(3, TimeUnit.MINUTES), "the run ends")
            val line = err.readText()
            record("first-part race: status ${cmd.exitValue()}, line <${line.trimEnd()}>")
            assertEquals(
                listOf(1, "", "andvari: backup stopped at the server, looked at again: the snapshot was made and checked, but this command cannot " +
                    "tell whether the lock on ${s.serverLock.path} is still held as it was when this run began (${firstPartOnly(s)}); tonight's " +
                    "snapshot was not kept, and no earlier snapshot was changed\n"),
                listOf(cmd.exitValue(), out.readText(), line),
            )
            assertNoNameGiven(s, snapshot, "first-part race")
        } finally {
            if (cmd.isAlive) cmd.destroyForcibly().waitFor()
            first?.destroyForcibly()?.waitFor()
            if (server.process.isAlive) server.kill()
        }
    }

    /**
     * (c) The start's own order: the real [ServerLock.take], called in this process (this process is then "the server"),
     * with the hook between the line and the second part, which only test code sets. In that hook the real command, a
     * process of its own, looks: the first part is held and the line written, the second part not yet: the cannot-tell
     * line word for word, status 1. Once the take is done, a process of its own finds both parts held, and the file
     * holds one line.
     */
    @Test
    fun theStartsOrder_aLookBetweenTheLineAndTheSecondPart_cannotTell() {
        val s = server()
        var between: Ran? = null
        ServerLock.letGoForTests()
        ServerLock.betweenLineAndSecondPart = { between = run(s) }
        try {
            assertEquals(null, ServerLock.take(s.db.path, ServerLock.keyBeforeOpen(s.db.path)), "the take holds both parts")
            assertRefused(assertNotNull(between, "the hook ran"), "andvari: backup stopped at the server: ${firstPartOnly(s)}, $cannotTell\n", "between the line and the second part")
            assertEquals("first refused, second refused", probe(s.serverLock, "shared"), "both parts held after the take")
            assertTrue(LINE.matches(s.serverLock.readText()), "one line: <${s.serverLock.readText()}>")
        } finally {
            ServerLock.betweenLineAndSecondPart = {}
            ServerLock.letGoForTests()
        }
    }

    /**
     * (d) After a real server's start, seen from a process of its own: a shared lock on the first part is refused, a
     * shared lock on the second part is refused, and the file holds one whole line. A second real server on the same
     * folder prints its warning, starts, and leaves the file byte for byte; once the first ends by the real SIGTERM, a
     * process of its own obtains both parts as exclusive locks, so the second server holds neither.
     */
    @Test
    fun afterARealStart_bothPartsAreHeld_theLineIsWhole_andASecondServerGetsNeitherPart() {
        val s = server()
        withServer(startServer(s)) { first ->
            assertEquals(emptyList(), lockWarnings(first), "the server took the lock")
            assertEquals("first refused, second refused", probe(s.serverLock, "shared"))
            val bytes = s.serverLock.readBytes()
            assertTrue(LINE.matches(String(bytes, Charsets.UTF_8)), "one whole line: <${String(bytes, Charsets.UTF_8)}>")
            withServer(startServer(s)) { second ->
                assertEquals(listOf(warning(s, "another process holds it")), lockWarnings(second), "the second server's line")
                assertTrue(second.process.isAlive && second.lines().any { it.contains(BackupFixture.LISTENING) }, "it starts: ${second.lines()}")
                assertTrue(bytes.contentEquals(s.serverLock.readBytes()), "the second server wrote nothing")
                assertEquals(143, first.term(), "the real SIGTERM")
                assertTrue(second.process.isAlive)
                assertEquals("first obtained, second obtained", probe(s.serverLock, "exclusive"), "the second server holds neither part")
                assertTrue(bytes.contentEquals(s.serverLock.readBytes()), "the file byte for byte")
            }
        }
    }

    /**
     * A server whose second part another process holds (a helper of this test that holds the second byte only, which no
     * server does): it prints its warning with that reason, lets go of the first part, and starts.
     */
    @Test
    fun aServerThatCannotTakeTheSecondPart_startsWithItsWarning_andHoldsNeitherPart() {
        val s = server()
        Files.createFile(s.serverLock.toPath())
        val second = holder(s.serverLock, "second")
        try {
            withServer(startServer(s)) { st ->
                assertEquals(listOf(warning(s, "another process holds a lock on its second byte")), lockWarnings(st), "the server's warning")
                assertTrue(st.process.isAlive && st.lines().any { it.contains(BackupFixture.LISTENING) }, "it starts: ${st.lines()}")
                second.destroyForcibly().waitFor()
                assertEquals("first obtained, second obtained", probe(s.serverLock, "exclusive"), "the server holds neither part")
            }
        } finally {
            second.destroyForcibly().waitFor()
        }
    }

    /**
     * (e) The real [ServerLock.take], in this process, given the identity of another file as the one read before the
     * database was opened: the warning with its reason; afterwards a process of its own obtains both parts, the file holds
     * no line of this start, and the command, a process of its own, then refuses.
     */
    @Test
    fun aTakeWhoseDatabaseFileIsNotTheOneThereBeforeTheOpen_warns_holdsNothing_andTheCommandRefuses() {
        val s = server()
        val another = assertNotNull(ServerLock.keyOf(s.env.path))
        ServerLock.letGoForTests()
        try {
            assertEquals(
                warning(s, "the file at ${s.db.path} is not the one that was there before the server opened its database"),
                ServerLock.take(s.db.path, another),
            )
            assertEquals("first obtained, second obtained", probe(s.serverLock, "exclusive"), "nothing is held")
            assertEquals("", s.serverLock.readText(), "no line of this start")
            assertRefused(run(s), noHolder(s), "the command then")
        } finally {
            ServerLock.letGoForTests()
        }
    }

    /**
     * A server folder whose real server was killed by the real SIGKILL after [rows] rows of about 2 000 bytes were saved
     * beside it with no checkpoint, so that all of them are still in the database's write-ahead file: the next start has
     * a large `-wal` to catch up before it takes its lock.
     */
    private fun killedWithALargeWriteAheadFile(rows: Int): Server {
        val s = server()
        withServer(startServer(s)) { st ->
            assertTrue(st.process.isAlive, "the server runs: ${st.lines()}")
            connect(s.db).use { c ->
                c.createStatement().use { it.execute("PRAGMA wal_autocheckpoint=0") }
                c.autoCommit = false
                c.prepareStatement("INSERT INTO meta(key,value) VALUES(?,?)").use { st2 ->
                    for (i in 1..rows) {
                        st2.setString(1, "saved before the kill $i")
                        st2.setString(2, "k$i".padEnd(2000, 'x'))
                        st2.addBatch()
                        if (i % 500 == 0) st2.executeBatch()
                    }
                    st2.executeBatch()
                }
                c.commit()
            }
            assertEquals(137, st.kill(), "the real SIGKILL")
        }
        val wal = File(s.db.path + "-wal")
        assertTrue(exists(wal) && wal.length() > 10L * 1024 * 1024, "the killed server left a large -wal: ${wal.length()} bytes")
        return s
    }

    /**
     * (f) The real start reads which file is at the database's path before it opens the database. A real server process
     * is started on the folder of a killed server with a large `-wal`; the test watches `/proc/<pid>/fd` and stops it by
     * the real SIGSTOP once its database file is open. Stopped, its open files must show the database and not
     * `server.lock`. Another valid database is then renamed onto the database's path, and the process goes on (SIGCONT):
     * it prints the warning that the file at the path is not the one that was there before it opened its database, no
     * part of the lock is held, and the command, a process of its own, stops at its first look with the line that nothing
     * holds the lock. A try whose stop came once `server.lock` was open, or where the database was no longer open at the
     * stop, missed that span and is made again in a fresh folder, at most ten times; the test fails if no try caught it.
     */
    @Test
    fun aRealStart_whoseDatabaseFileIsReplacedAfterItsOpenAndBeforeItsLock_warns_holdsNothing_andTheCommandRefuses() {
        val missed = ArrayList<String>()
        for (n in 1..10) {
            val s = killedWithALargeWriteAheadFile(10_000)
            val another = server()
            val started = BackupFixture.startServerAtOnce(s)
            try {
                val pid = started.process.pid()
                val end = System.nanoTime() + TimeUnit.MINUTES.toNanos(1)
                var stopped = false
                while (System.nanoTime() < end && started.process.isAlive) {
                    if (fds(pid).any { it == s.db.path }) {
                        signal("STOP", pid)
                        stopped = true
                        break
                    }
                }
                if (!stopped) {
                    missed += "try $n: the database was never seen open (${started.lines()})"
                    continue
                }
                val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5)
                while (stateOf(pid) !in setOf("T", "t") && System.nanoTime() < deadline) Thread.sleep(2)
                assertTrue(stateOf(pid) in setOf("T", "t"), "the server is stopped")
                val open = fds(pid)
                if (open.any { it == s.serverLock.path }) {
                    missed += "try $n: server.lock was already open at the stop"
                    continue
                }
                if (open.none { it == s.db.path }) {
                    missed += "try $n: the database was not open at the stop"
                    continue
                }
                Files.move(another.db.toPath(), s.db.toPath(), StandardCopyOption.REPLACE_EXISTING)
                signal("CONT", pid)
                assertTrue(started.waitFor(BackupFixture.LISTENING) && started.process.isAlive, "the server starts: ${started.lines()}")
                record("a database file replaced within the start: caught at try $n (missed before: $missed); warnings ${lockWarnings(started)}")
                assertEquals(
                    listOf(warning(s, "the file at ${s.db.path} is not the one that was there before the server opened its database")),
                    lockWarnings(started),
                    "the server's warning",
                )
                assertEquals("first obtained, second obtained", probe(s.serverLock, "exclusive"), "no part of the lock is held")
                assertRefused(run(s), noHolder(s), "the command then")
                return
            } finally {
                if (started.process.isAlive) started.kill()
            }
        }
        fail("no try of ten stopped the start between the open of its database and its open of server.lock: $missed")
    }
}
