package io.silencelen.andvari.server

import io.silencelen.andvari.server.BackupFixture.Ran
import io.silencelen.andvari.server.BackupFixture.Server
import io.silencelen.andvari.server.BackupFixture.Started
import io.silencelen.andvari.server.BackupFixture.connect
import io.silencelen.andvari.server.BackupFixture.copyAside
import io.silencelen.andvari.server.BackupFixture.exists
import io.silencelen.andvari.server.BackupFixture.header
import io.silencelen.andvari.server.BackupFixture.inode
import io.silencelen.andvari.server.BackupFixture.newFolder
import io.silencelen.andvari.server.BackupFixture.process
import io.silencelen.andvari.server.BackupFixture.server
import io.silencelen.andvari.server.BackupFixture.startServer
import io.silencelen.andvari.server.BackupFixture.tree
import io.silencelen.andvari.server.BackupFixture.withoutOverride
import java.io.File
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.nio.file.attribute.PosixFilePermissions
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * The first step of `andvari admin backup`, the look at `server.lock` (decided on 2026-11-22): a snapshot is taken only
 * while a running server holds the database. The holder in every test here is the server's real start (`java … MainKt`,
 * the program the image runs) in a process of its own, on a real data folder made by the product's own setup, stopped by
 * the real SIGTERM or SIGKILL or dying at its listen; the command is the real program in a process of its own, except
 * where a test says it runs in this process (the command's own code, beside a server in another process). No test here
 * takes the seam that tells a run a server holds the database. Not real: the classes and libraries come from this test's
 * class path rather than the image's jar.
 */
class ServerBackupLookTest {
    private val cannotTell = "so this command cannot tell whether a running server holds the database. No snapshot was taken, and nothing was changed."

    private val noHolderRest =
        "This command looks for a running server by that lock, and takes a snapshot only where it finds the lock held for the " +
            "database file it would open. No snapshot was taken, and nothing was changed."

    /** The line of a run where the file is there and nothing holds its lock, word for word. */
    private fun noHolder(s: Server) = "andvari: backup stopped at the server: nothing holds the lock on ${s.serverLock.path}. $noHolderRest\n"

    /** The line of a run where there is no `server.lock`, word for word. */
    private fun missing(s: Server) =
        "andvari: backup stopped at the server: there is no ${s.serverLock.path}, so nothing holds the lock on that file. $noHolderRest\n"

    /** The server's one line where it could not take the lock, for the reason [why], word for word. */
    private fun warning(s: Server, why: String) =
        "[andvari] WARNING: the server could not take the lock on ${s.serverLock.path} ($why) and starts without it. " +
            "`andvari admin backup` takes a snapshot only while a process holds the lock on that file."

    private fun run(s: Server): Ran = process("admin", "backup", "--env-file", s.env.path)

    private fun assertWorked(r: Ran, what: String) {
        assertEquals(listOf(0, "", ""), listOf(r.code, r.out, r.err), "$what: a run that works prints nothing and ends with status 0")
    }

    private fun assertRefused(r: Ran, line: String, what: String) {
        assertEquals(listOf(1, "", line), listOf(r.code, r.out, r.err), "$what: status 1 and the one line")
    }

    /**
     * What a run beside a running server may not change: every file of the data folder but the running server's own
     * write-ahead and shared-memory files and its mail sink, which it writes while it runs.
     */
    private fun besideARunningServer(s: Server): Map<String, String> =
        tree(s.data).filterKeys { it != "andvari.db-wal" && it != "andvari.db-shm" && !it.startsWith("mail-sink") }

    private fun <T> withServer(started: Started, block: (Started) -> T): T = try {
        block(started)
    } finally {
        if (started.process.isAlive) started.kill()
    }

    private fun lockWarnings(started: Started) = started.lines().filter { it.startsWith("[andvari] WARNING: the server could not take the lock") }

    // ---------------------------------------------------------------------------------------------------------------
    // A running server
    // ---------------------------------------------------------------------------------------------------------------

    /** The real start takes the lock (the file made owner-only), and a run beside it takes its snapshot and prints nothing. */
    @Test
    fun aRunningServer_holdsTheLock_andARunTakesItsSnapshot() {
        val s = server()
        withServer(startServer(s)) { server ->
            assertTrue(server.process.isAlive, "the server runs: ${server.lines()}")
            assertEquals(emptyList(), lockWarnings(server), "the server took the lock")
            assertTrue(exists(s.serverLock) && Files.isRegularFile(s.serverLock.toPath()), "the start made ${s.serverLock}")
            assertEquals("rw-------", PosixFilePermissions.toString(Files.getPosixFilePermissions(s.serverLock.toPath())))
            assertTrue(Regex("server [0-9a-f]{32} database \\S+\n").matches(s.serverLock.readText()), "the file holds the server's one line")
            assertWorked(run(s), "beside a running server")
            assertEquals(inode(s.dated(BackupFixture.NIGHT_1)), inode(s.nightly))
        }
    }

    // ---------------------------------------------------------------------------------------------------------------
    // A server that stopped: no server
    // ---------------------------------------------------------------------------------------------------------------

    /**
     * A server that ran (a run took its snapshot meanwhile) and then ended by [stop]: its write-ahead and shared-memory
     * files are left beside the database, and its `server.lock` is left unlocked. A run is refused at the server with its
     * line, and no byte of the database, its `-wal`, its `-shm` or the backup folder changes.
     */
    private fun assertAStoppedServerIsNoServer(what: String, stop: (Server, Started) -> Unit) {
        val s = server()
        withServer(startServer(s)) { server ->
            assertWorked(run(s), "$what: while it ran")
            stop(s, server)
        }
        assertTrue(exists(File(s.db.path + "-wal")) && exists(File(s.db.path + "-shm")), "$what: the -wal and the -shm are left: ${s.data.list()!!.toList()}")
        assertTrue(exists(s.serverLock), what)
        val before = tree(s.data)
        assertRefused(run(s), noHolder(s), what)
        assertEquals(before, tree(s.data), "$what: the database, its -wal, its -shm and the backup folder keep every byte; nothing is made")
    }

    @Test
    fun aServerStoppedBySigterm_isNoServer_andARunChangesNoByte() {
        assertAStoppedServerIsNoServer("stopped by SIGTERM") { _, server -> assertEquals(143, server.term()) }
    }

    @Test
    fun aServerStoppedBySigkill_isNoServer_andARunChangesNoByte() {
        assertAStoppedServerIsNoServer("stopped by SIGKILL") { _, server -> assertEquals(137, server.kill()) }
    }

    /** A server whose start opened the database and then died at its listen (an address it cannot have). */
    @Test
    fun aServerThatDiedAtItsListen_isNoServer_andARunChangesNoByte() {
        assertAStoppedServerIsNoServer("died at its listen") { s, first ->
            assertEquals(143, first.term())
            val dead = startServer(s, "ANDVARI_HOST" to "192.0.2.1")
            assertTrue(dead.ended() != 0, "the start on an address it cannot have ends")
            assertTrue(dead.lines().any { it.contains("BindException") }, "it died at its listen: ${dead.lines()}")
            assertTrue(dead.lines().any { it.contains(BackupFixture.LISTENING) }, "after its database was open")
            assertEquals(emptyList(), lockWarnings(dead), "it had taken the lock")
        }
    }

    /** A data folder where no server ever started: no `server.lock`; the run makes none, and no backup folder. */
    @Test
    fun aFolderWhereNoServerEverStarted_isRefused_andNeitherTheLockFileNorTheBackupFolderIsMade() {
        val s = server()
        val before = tree(s.data)
        assertFalse(exists(s.serverLock))
        assertRefused(run(s), missing(s), "never started")
        assertEquals(before, tree(s.data), "nothing is made or changed")
        assertFalse(exists(s.serverLock), "the command makes no lock file")
        assertFalse(exists(s.backup), "and no backup folder")
    }

    /**
     * A snapshot put back as the database (rollback mode), with the stale write-ahead and shared-memory files of the
     * replaced database beside it and the stopped server's unlocked `server.lock`: refused at the server, before the
     * leftover guard, and no byte changes.
     */
    @Test
    fun aPutBackSnapshotWithAStaleWriteAheadFileBesideAnUnlockedLockFile_isRefusedAtTheServer() {
        val s = server()
        withServer(startServer(s)) { server ->
            assertWorked(run(s), "while it ran")
            connect(s.db).use { it.exec("INSERT INTO meta(key,value) VALUES('saved while it ran','1')") }
            assertEquals(137, server.kill())
        }
        val putBack = copyAside(s.nightly).also { c -> connect(c).use { it.queryOne("PRAGMA journal_mode=DELETE") { r -> r.getString(1) } } }
        Files.copy(putBack.toPath(), s.db.toPath(), StandardCopyOption.REPLACE_EXISTING)
        assertEquals("header 1/1", header(s.db))
        assertTrue(exists(File(s.db.path + "-wal")) && exists(s.serverLock))
        val before = tree(s.data)
        assertRefused(run(s), noHolder(s), "a put-back snapshot")
        assertEquals(before, tree(s.data), "the put-back file, the stale files beside it and the backup folder keep every byte")
    }

    // ---------------------------------------------------------------------------------------------------------------
    // Two runs, two servers, a server that starts while a run looks
    // ---------------------------------------------------------------------------------------------------------------

    /**
     * Two runs at once without a server: a run of the command in this process holds its look's shared lock (held there by
     * its hook) while a run in a process of its own looks. Neither takes the other for a server: both are refused with the
     * line, and nothing changes.
     */
    @Test
    fun twoRunsAtOnceWithoutAServer_areBothRefused() {
        val s = server()
        withServer(startServer(s)) { server -> assertEquals(137, server.kill()) }
        val before = tree(s.data)
        var second: Ran? = null
        val first = BackupFixture.backup(s, seams = ServerBackup.Seams(looking = { if (second == null) second = run(s) }))
        assertEquals(noHolder(s), "andvari: $first\n", "the run in this process")
        assertRefused(second!!, noHolder(s), "the run in a process of its own, while the first looked")
        assertEquals(before, tree(s.data))
    }

    /**
     * A second server started on the same folder while the first holds the lock: it tries, prints its line and starts.
     * While both run, a run takes its snapshot (the first holds the lock). Once the first is stopped, the second runs
     * without the lock, and a run is refused at the server with the line.
     */
    @Test
    fun aSecondServerOnTheSameFolder_startsWithTheWarning_andARunWorksOnlyWhileTheFirstHoldsTheLock() {
        val s = server()
        withServer(startServer(s)) { first ->
            withServer(startServer(s)) { second ->
                assertEquals(listOf(warning(s, "another process holds it")), lockWarnings(second), "the second server's line")
                assertTrue(second.lines().any { it.contains(BackupFixture.LISTENING) } && second.process.isAlive, "the second server starts: ${second.lines()}")
                assertEquals(emptyList(), lockWarnings(first))
                assertWorked(run(s), "while both run")
                assertEquals(143, first.term())
                assertTrue(second.process.isAlive)
                val before = besideARunningServer(s)
                assertRefused(run(s), noHolder(s), "the second server alone")
                assertEquals(before, besideARunningServer(s))
            }
        }
    }

    /**
     * A server that starts while a run looks: the run (the command's own code in this process) holds its look's shared lock
     * while the server's real start, in a process of its own, opens its database and tries for the lock. The run found no
     * holder and is refused; the server takes the lock once the run has let go, within its tries, and prints no line of
     * its own; the next run works. Whether the server's tries began before the run let go depends on how fast its start
     * opened the database; the look is held for 1.5 seconds after the start's first line, within the start's two seconds.
     */
    @Test
    fun aServerStartingWhileARunLooks_takesTheLockOnceTheRunHasLetGo() {
        val s = server()
        withServer(startServer(s)) { server -> assertEquals(137, server.kill()) }
        var started: Started? = null
        try {
            val line = BackupFixture.backup(
                s,
                seams = ServerBackup.Seams(
                    looking = {
                        if (started == null) {
                            started = startServer(s, "ANDVARI_SET_BY_THE_LOOK_TEST" to "1", until = "env WARNING")
                            Thread.sleep(1_500)
                        }
                    },
                ),
            )
            assertEquals(noHolder(s), "andvari: $line\n", "the run looked before the server held the lock")
            val server = started!!
            assertTrue(server.waitFor(BackupFixture.LISTENING), "the server starts: ${server.lines()}")
            assertEquals(emptyList(), lockWarnings(server), "the server took the lock once the run let go")
            assertWorked(run(s), "the next run")
        } finally {
            started?.let { if (it.process.isAlive) it.kill() }
        }
    }

    // ---------------------------------------------------------------------------------------------------------------
    // A server that cannot take the lock; the file removed under a running server
    // ---------------------------------------------------------------------------------------------------------------

    /**
     * A server whose `server.lock` is a folder, a link (dangling, to a file elsewhere) or a file it may not write (the
     * process runs without the capabilities by which root writes past a file's mode, see [withoutOverride]): it prints its
     * line and starts. A run is refused at the server with the line its state gives, and changes nothing; nothing is made
     * where the link leads.
     */
    @Test
    fun aServerThatCannotTakeTheLock_startsWithItsLine_andARunIsRefusedAtTheServer() {
        for (kind in listOf("a folder", "a link", "a file it may not write")) {
            val s = server()
            val elsewhere = newFolder("elsewhere")
            val (why, line) = when (kind) {
                "a folder" -> {
                    Files.createDirectory(s.serverLock.toPath())
                    "it is not an ordinary file" to "andvari: backup stopped at the server: ${s.serverLock.path} is not an ordinary file, $cannotTell\n"
                }
                "a link" -> {
                    Files.createSymbolicLink(s.serverLock.toPath(), File(elsewhere, "not-there").toPath())
                    "it is a link, and the server follows no link to it" to
                        "andvari: backup stopped at the server: ${s.serverLock.path} is a link, which this command does not follow, $cannotTell\n"
                }
                else -> {
                    Files.createFile(s.serverLock.toPath(), PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("r--------")))
                    Files.setPosixFilePermissions(s.serverLock.toPath(), PosixFilePermissions.fromString("r--------"))
                    "it could not be opened for writing: permission denied" to noHolder(s)
                }
            }
            withServer(startServer(s, before = if (kind == "a file it may not write") withoutOverride() else emptyList())) { server ->
                assertEquals(listOf(warning(s, why)), lockWarnings(server), "$kind: the server's line")
                assertTrue(server.lines().any { it.contains(BackupFixture.LISTENING) } && server.process.isAlive, "$kind: the server starts: ${server.lines()}")
                val before = besideARunningServer(s)
                assertRefused(run(s), line, kind)
                assertEquals(before, besideARunningServer(s), "$kind: nothing changed")
                assertFalse(exists(s.backup), "$kind: no backup folder")
                assertEquals(emptyMap(), tree(elsewhere).filterKeys { it.isNotEmpty() }, "$kind: nothing made where a link leads")
            }
        }
    }

    /**
     * `server.lock` moved out of the data folder while the server runs: there is no such file; the run is refused at the
     * server and makes none, and the server runs on.
     */
    @Test
    fun theLockFileMovedOutUnderARunningServer_isRefusedAtTheServer_andTheCommandMakesNone() {
        val s = server()
        withServer(startServer(s)) { server ->
            assertWorked(run(s), "before the file was moved")
            Files.move(s.serverLock.toPath(), File(newFolder("moved-out"), ServerLock.NAME).toPath())
            val before = besideARunningServer(s)
            assertRefused(run(s), missing(s), "the file moved out")
            assertEquals(before, besideARunningServer(s))
            assertFalse(exists(s.serverLock), "the command makes no lock file")
            assertTrue(server.process.isAlive)
        }
    }
}
