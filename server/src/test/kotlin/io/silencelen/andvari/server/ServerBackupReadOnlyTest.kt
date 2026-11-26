package io.silencelen.andvari.server

import io.silencelen.andvari.server.BackupFixture.connect
import io.silencelen.andvari.server.BackupFixture.exists
import io.silencelen.andvari.server.BackupFixture.header
import io.silencelen.andvari.server.BackupFixture.newFolder
import io.silencelen.andvari.server.BackupFixture.rows
import io.silencelen.andvari.server.BackupFixture.server
import io.silencelen.andvari.server.BackupFixture.startServer
import org.sqlite.SQLiteConfig
import java.io.File
import java.nio.file.Files
import java.sql.Connection
import java.sql.DriverManager
import java.sql.SQLException
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlin.test.fail

/**
 * What a connection opened in the driver's read-only open mode does to a database in write-ahead mode, over the real
 * library the server uses and the server's real start in a process of its own, stopped by the real signal: the backup
 * command's one connection to the database is opened so. (a) It takes the snapshot the way the command takes it
 * (`VACUUM INTO`) beside a running server, and the system refuses its write: the file is open for reading only, and a
 * write through it fails. (b) When it is the last connection to close, after the server's process ended, the database
 * file keeps every byte and its write-ahead file stays; a connection opened for reading and writing, in the same state,
 * merges the write-ahead file into the database at its close.
 */
class ServerBackupReadOnlyTest {
    private fun readOnly(db: File): Connection =
        DriverManager.getConnection("jdbc:sqlite:${db.path}", SQLiteConfig().apply { setReadOnly(true) }.toProperties())

    /** The access mode of every opening of [f] in this process, from `/proc/self/fdinfo`: 0 for reading only. */
    private fun accessModesOf(f: File): List<Int> {
        val target = f.toPath().toRealPath()
        return (File("/proc/self/fd").listFiles() ?: emptyArray()).mapNotNull { fd ->
            val to = runCatching { Files.readSymbolicLink(fd.toPath()) }.getOrNull() ?: return@mapNotNull null
            if (to != target) return@mapNotNull null
            val flags = runCatching { File("/proc/self/fdinfo/${fd.name}").readLines().first { it.startsWith("flags:") } }.getOrNull()
                ?: return@mapNotNull null
            (flags.substringAfter(":").trim().toInt(8)) and 3
        }
    }

    private fun bytes(f: File): ByteArray = Files.readAllBytes(f.toPath())

    @Test
    fun aReadOnlyConnection_takesTheSnapshotBesideARunningServer_andTheSystemRefusesItsWrite() {
        val s = server()
        val started = startServer(s)
        try {
            assertTrue(started.process.isAlive, "the server runs: ${started.lines()}")
            connect(s.db).use { c -> for (i in 1..5) c.exec("INSERT INTO meta(key,value) VALUES(?,?)", "saved while it ran $i", "1") }
            assertTrue(exists(File(s.db.path + "-wal")), "the running server's write-ahead file")
            assertEquals(emptyList(), accessModesOf(s.db), "no opening of the database in this process before")
            val into = File(newFolder("read-only-snapshot"), "snapshot.db")
            readOnly(s.db).use { c ->
                c.createStatement().use { st ->
                    st.execute("PRAGMA busy_timeout=5000")
                    st.execute("PRAGMA synchronous=FULL")
                }
                assertFalse(Db.decide(c), "the start's decision, on this connection")
                c.prepareStatement("VACUUM INTO ?").use { st ->
                    st.setString(1, into.path)
                    st.execute()
                }
                val modes = accessModesOf(s.db)
                assertTrue(modes.isNotEmpty() && modes.all { it == 0 }, "the database is open in this process for reading only: $modes")
                val refused = try {
                    c.exec("INSERT INTO meta(key,value) VALUES('written through the read-only connection','1')")
                    null
                } catch (e: SQLException) {
                    e.message
                }
                assertTrue(refused != null && refused.contains("SQLITE_READONLY"), "the write is refused: $refused")
                println("evidence (a): access modes $modes; the write: $refused")
            }
            val snapshot = rows(into)
            assertTrue(snapshot.any { it.contains("saved while it ran 5") }, "the snapshot holds the saves: $snapshot")
            assertEquals(listOf("ok"), connect(into).use { c -> c.queryAll("PRAGMA integrity_check") { it.getString(1) } })
            assertFalse(rows(s.db).any { it.contains("written through the read-only connection") })
        } finally {
            if (started.process.isAlive) started.kill()
        }
    }

    /**
     * A server that ran and wrote, a connection of this process opened on its database while it ran, then the server
     * stopped by the real SIGTERM: the connection is the last one, and its close is the first after the server's.
     */
    private fun lastToClose(open: (File) -> Connection): Triple<Boolean, Boolean, String> {
        val s = server()
        val started = startServer(s)
        val c: Connection
        try {
            assertTrue(started.process.isAlive, "the server runs: ${started.lines()}")
            connect(s.db).use { w -> for (i in 1..5) w.exec("INSERT INTO meta(key,value) VALUES(?,?)", "saved while it ran $i", "1") }
            c = open(s.db)
            c.queryOne("SELECT COUNT(*) FROM meta") { it.getLong(1) }
            assertEquals(143, started.term(), "the real SIGTERM")
        } finally {
            if (started.process.isAlive) started.kill()
        }
        val wal = File(s.db.path + "-wal")
        assertTrue(exists(wal) && wal.length() > 0, "the stopped server's write-ahead file is left")
        val before = bytes(s.db)
        val headerBefore = header(s.db)
        c.close()
        val same = bytes(s.db).contentEquals(before)
        return Triple(same, exists(wal), "$headerBefore, ${before.size} bytes before, ${s.db.length()} after, -wal ${if (exists(wal)) "${wal.length()} bytes" else "gone"}")
    }

    @Test
    fun aReadOnlyConnectionThatClosesLast_leavesTheDatabaseByteForByte_andItsWriteAheadFile() {
        val (same, walStays, what) = lastToClose(::readOnly)
        println("evidence (b), read-only: $what")
        assertTrue(same, "the database keeps every byte: $what")
        assertTrue(walStays, "the write-ahead file stays: $what")
        // The same state, the connection opened for reading and writing: its close merges the write-ahead file.
        val (rwSame, rwWal, rwWhat) = lastToClose { db -> connect(db) }
        println("evidence (b), read-write: $rwWhat")
        if (rwSame && rwWal) fail("a read-write connection changed nothing either, so this test sees nothing: $rwWhat")
    }

    /** The files of the data folder of [s] other than folders, each with its size. */
    private fun filesIn(s: BackupFixture.Server): Map<String, Long> =
        s.data.listFiles()!!.filter { it.isFile }.associate { it.name to it.length() }

    /**
     * A run with the looks taken out by the seam, on a database in write-ahead mode that nothing has open (no `-wal` and no
     * `-shm` beside it): the command is called directly here, not through the fixture, which would hold the database open.
     * The read-only open leaves exactly two new files beside the database, an empty `andvari.db-wal` and an
     * `andvari.db-shm` of 32768 bytes, and `andvari.db` keeps every byte. A backup then written over `andvari.db` in place
     * with those two files left lying: `andvari admin restored`, a process of its own, gives its line and status 1; with
     * the two files moved aside (into a folder of this test), it gives status 0. And a real server started on its own
     * database with such an empty `-wal` and `-shm` beside it listens.
     */
    @Test
    fun withTheLooksTakenOut_onADatabaseNothingHasOpen_theReadOnlyOpenLeavesTwoFiles_whichRestoredNames_andAStartListensBesideThem() {
        val s = server()
        val dbBytes = bytes(s.db)
        val before = filesIn(s)
        assertFalse(exists(File(s.db.path + "-wal")) || exists(File(s.db.path + "-shm")), "nothing has the database open")
        ServerBackup.command(HostCli.Args(listOf("backup", "--env-file", s.env.path)), s.env, ServerBackup.Seams(serverHolds = true))
        val made = filesIn(s) - before.keys
        assertEquals(mapOf("andvari.db-wal" to 0L, "andvari.db-shm" to 32768L), made, "exactly two new files beside the database")
        assertTrue(bytes(s.db).contentEquals(dbBytes), "andvari.db keeps every byte")

        val snapshot = bytes(s.nightly)
        java.io.FileOutputStream(s.db).use { it.write(snapshot) }
        val leftOver = BackupFixture.process("admin", "restored", "--env-file", s.env.path)
        assertEquals(
            listOf(
                1, "",
                "andvari: Left over beside the database: andvari.db-wal and andvari.db-shm. If the server is running, stop the server " +
                    "(and anything else that has the database open) first. Whatever left them there: move andvari.db-wal and " +
                    "andvari.db-shm out of this folder and keep them; copy the backup's andvari.db into place again (copy it, never " +
                    "move it, and keep the backup until the restore has worked); then run `andvari admin restored` again. If you no " +
                    "longer have the backup's andvari.db, move nothing and do not start the server. Nothing was changed.\n",
            ),
            listOf(leftOver.code, leftOver.out, leftOver.err),
            "restored beside the two files",
        )
        val aside = newFolder("moved-aside")
        for (name in made.keys) Files.move(File(s.data, name).toPath(), File(aside, name).toPath())
        val restored = BackupFixture.process("admin", "restored", "--env-file", s.env.path)
        assertEquals(0, restored.code, "restored with the two files moved aside: ${restored.out} ${restored.err}")

        val t = server()
        ServerBackup.command(HostCli.Args(listOf("backup", "--env-file", t.env.path)), t.env, ServerBackup.Seams(serverHolds = true))
        assertEquals(mapOf("andvari.db-wal" to 0L, "andvari.db-shm" to 32768L), filesIn(t).filterKeys { it.startsWith("andvari.db-") }, "the two files beside it")
        val started = startServer(t)
        try {
            assertTrue(started.process.isAlive && started.lines().any { it.contains(BackupFixture.LISTENING) }, "it listens: ${started.lines()}")
        } finally {
            if (started.process.isAlive) started.kill()
        }
    }
}
