package io.silencelen.andvari.server

import io.silencelen.andvari.server.BackupFixture.NIGHT_1
import io.silencelen.andvari.server.BackupFixture.NIGHT_2
import io.silencelen.andvari.server.BackupFixture.Ran
import io.silencelen.andvari.server.BackupFixture.backup
import io.silencelen.andvari.server.BackupFixture.exists
import io.silencelen.andvari.server.BackupFixture.heldRun
import io.silencelen.andvari.server.BackupFixture.inode
import io.silencelen.andvari.server.BackupFixture.process
import io.silencelen.andvari.server.BackupFixture.server
import io.silencelen.andvari.server.BackupFixture.startServer
import io.silencelen.andvari.server.BackupFixture.stoppedWriter
import io.silencelen.andvari.server.BackupFixture.tree
import io.silencelen.andvari.server.BackupFixture.withoutOverride
import io.silencelen.andvari.server.ServerBackup.Seams
import io.silencelen.andvari.server.ServerBackup.Step
import java.io.File
import java.io.FileOutputStream
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.nio.file.attribute.PosixFilePermissions
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * `andvari admin backup` run as the server's program in a process of its own (`java … MainKt admin backup …`, the
 * program the image runs), over a real data folder and the real library, beside the server's real start in a process
 * of its own where the run must find a running server: what it prints, its status, and two runs at once. Not real: the
 * classes and libraries come from this test's class path rather than the image's jar, and the clock is the server's
 * test clock file.
 */
class ServerBackupProcessTest {
    private fun assertOneLine(r: Ran, start: String): String {
        assertEquals(1, r.code, "status 1: ${r.err}")
        assertEquals("", r.out, "nothing on standard output")
        assertTrue(r.err.endsWith("\n") && r.err.count { it == '\n' } == 1, "exactly one line on standard error: <${r.err}>")
        assertTrue(r.err.startsWith(start), "<${r.err}> begins with <$start>")
        return r.err
    }

    /** The server's real start in a process of its own on [s] ([startServer]) for the time of [block], then killed. */
    private fun <T> besideARunningServer(s: BackupFixture.Server, block: () -> T): T {
        val started = startServer(s)
        try {
            check(started.process.isAlive) { "the server did not start: ${started.lines()}" }
            return block()
        } finally {
            started.kill()
        }
    }

    /**
     * Beside a running server (its real start, in a process of its own): a run that works ends with status 0 and prints
     * nothing; a run that fails prints one line and ends with status 1.
     */
    @Test
    fun aRunPrintsNothingAndEndsWithStatus0_orOneLineAndStatus1() {
        val s = server()
        besideARunningServer(s) { aRunPrintsNothing(s) }
    }

    private fun aRunPrintsNothing(s: BackupFixture.Server) {
        val good = process("admin", "backup", "--env-file", s.env.path)
        assertEquals(0, good.code, good.err)
        assertEquals("", good.out)
        assertEquals("", good.err)
        assertEquals(inode(s.dated(NIGHT_1)), inode(s.nightly))

        assertOneLine(process("admin", "backup", "--env-file", s.env.path, "--keep", "0"), "andvari: backup stopped at its arguments: ")
        assertOneLine(process("admin", "backup", "--env-file", s.env.path, "before-1.0.1"), "andvari: backup stopped at its arguments: ")
        assertOneLine(process("admin", "backup", "--env-file", s.env.path), "andvari: backup stopped at the dated name: ")
        assertOneLine(process("admin", "backup", "--env-file", File(s.root, "missing.env").path), "andvari: backup stopped at the server's settings: ")

        // A database the server's start refuses (a stray write-ahead file beside a database in rollback mode, as a restore
        // that left the replaced database's file beside the put-back one), here put in place under the running server,
        // which holds the lock: the one plain line of a header that does not say write-ahead mode, from the process too. The
        // snapshot is written over the database file in place (the same file, as `cp` writes it), so the server's line still
        // names it.
        s.at(NIGHT_2)
        val wal = File(s.db.path + "-wal")
        FileOutputStream(s.db).use { it.write(s.nightly.readBytes()) }
        wal.writeText("a write-ahead file of another database")
        val err = assertOneLine(process("admin", "backup", "--env-file", s.env.path), "andvari: backup stopped at the database: ")
        assertEquals(
            "andvari: backup stopped at the database: the header of the database file ${s.db.path} does not say write-ahead mode. " +
                "No snapshot was taken, and nothing was changed.\n",
            err,
        )
        // The same snapshot put in place as a new file of that name: the server's line names the file it opened, which is
        // no longer the one at the path, and the run is refused at the server.
        Files.copy(s.nightly.toPath(), s.db.toPath(), StandardCopyOption.REPLACE_EXISTING)
        assertEquals(
            "andvari: backup stopped at the server: a process holds the lock on ${s.serverLock.path}, and the line in that file names " +
                "another database file than the one at ${s.db.path}. This command looks for a running server by that lock, and takes " +
                "a snapshot only where it finds the lock held for the database file it would open. No snapshot was taken, and nothing " +
                "was changed.\n",
            assertOneLine(process("admin", "backup", "--env-file", s.env.path), "andvari: backup stopped at the server: "),
        )
    }

    /**
     * A rollback journal beside a database whose header this user cannot read (the file's mode lets nobody read it; as
     * root, the process runs without the capabilities that read past a file's mode, see [withoutOverride]), beside a
     * running server: the run ends in the plain line for a database it cannot open, before anything opens it, and no byte
     * changes (but those of the running server's own write-ahead and shared-memory files and mail sink).
     */
    @Test
    fun aJournalBesideADatabaseWhoseHeaderCannotBeRead_endsInTheLineForADatabaseThatCannotBeOpened() {
        val s = server()
        assertNull(backup(s))
        val other = server()
        assertNull(backup(other))
        fun files() = tree(s.data).filterKeys { it != "andvari.db-wal" && it != "andvari.db-shm" && !it.startsWith("mail-sink") }
        val line = besideARunningServer(s) {
            Files.copy(File(stoppedWriter(other.nightly).path + "-journal").toPath(), File(s.db.path + "-journal").toPath())
            s.at(NIGHT_2)
            Files.setPosixFilePermissions(s.db.toPath(), PosixFilePermissions.fromString("---------"))
            val data = files()
            val r = process("admin", "backup", "--env-file", s.env.path, before = withoutOverride())
            assertEquals(data, files(), "the database, the journal and the backup folder keep every byte")
            assertOneLine(r, "andvari: backup stopped at the database: ")
        }
        assertEquals(
            "andvari: backup stopped at the database: could not open the database ${s.db.path} (${s.db.path} (Permission denied)): " +
                "check that its folder exists and that its owner and permissions let this user open it\n",
            line,
        )
    }

    /**
     * Two runs at once beside a running server (its real start, in a process of its own): the first run, in this
     * process, holds the lock while a second run, a process of its own, is started; the second refuses at the lock with
     * one line and status 1. Afterwards a third process runs: the lock file left in place blocks no later run. Both runs
     * make the real look at the server. Stand-in: the first run is held at its room step by the step hook, from which the
     * second process is started and waited for.
     */
    @Test
    fun twoRunsAtOnce_theSecondProcessRefusesWithALine() {
        val s = server()
        besideARunningServer(s) {
            var second: Ran? = null
            assertNull(backup(s, seams = Seams(atStep = { if (it == Step.ROOM && second == null) second = process("admin", "backup", "--env-file", s.env.path) })))
            val line = assertOneLine(assertNotNull(second), "andvari: backup stopped at the lock: ")
            assertTrue(line.contains("another run"), line)
            assertEquals(inode(s.dated(NIGHT_1)), inode(s.nightly), "the first run finished")

            s.at(NIGHT_2)
            assertTrue(exists(s.lock))
            val third = process("admin", "backup", "--env-file", s.env.path)
            assertEquals(0, third.code, third.err)
            assertEquals(inode(s.dated(NIGHT_2)), inode(s.nightly))
        }
    }

    /**
     * A run in a process of its own, killed while it holds the lock (at its room step): while it lives, a run is refused
     * at the lock; once it is killed, the system has released its lock with the process, and the next run works, although
     * the lock file it opened is still there.
     */
    @Test
    fun theLockOfARunThatIsKilled_isReleasedWithItsProcess() {
        val s = server()
        assertNull(backup(s))
        s.at(NIGHT_2)
        val held = heldRun(s)
        try {
            val line = assertNotNull(backup(s))
            assertTrue(line.startsWith("backup stopped at the lock: ") && line.contains("another run"), line)
        } finally {
            held.destroyForcibly()
            assertTrue(held.waitFor(1, TimeUnit.MINUTES), "the held run was killed")
        }
        assertTrue(exists(s.lock))
        assertFalse(exists(s.dated(NIGHT_2)), "the killed run gave no dated name")
        assertNull(backup(s))
        assertEquals(inode(s.dated(NIGHT_2)), inode(s.nightly))
    }
}
