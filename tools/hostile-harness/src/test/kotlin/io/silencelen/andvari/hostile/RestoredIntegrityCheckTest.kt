package io.silencelen.andvari.hostile

import io.silencelen.andvari.cli.e2e.synced
import io.silencelen.andvari.server.HostCli
import java.io.File
import java.io.RandomAccessFile
import java.nio.file.Files
import java.security.MessageDigest
import java.sql.DriverManager
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * `andvari admin restored` runs SQLite's integrity check on the put-back database before it changes anything, the check the
 * snapshot command runs on a new snapshot (decided on 22 November 2026). A file that fails it is refused with nothing
 * changed: the folder's listing and every file's bytes are as they were, no session is ended and no change is counted. The
 * refusals for files left beside the database come first, as before, and the check is not reached.
 */
class RestoredIntegrityCheckTest {
    /** A copy of [s] put back in a new directory of its own, with an environment file naming it; [extra] runs on the directory first. */
    private fun World.putBack(s: Snapshot, label: String, extra: (File) -> Unit = {}): Pair<File, File> {
        val dir = Files.createTempDirectory(server.dir.toPath(), label).toFile()
        val db = s.db.copyTo(File(dir, "andvari.db"))
        val blobs = File(dir, "blobs").apply { mkdirs() }
        s.blobs.copyRecursively(blobs, overwrite = true)
        extra(dir)
        val env = File(dir, "andvari.env")
        env.writeText(server.envFile.readText())
        HostCli.editEnvFile(env, mapOf("ANDVARI_DB" to db.path, "ANDVARI_BLOB_DIR" to blobs.path))
        return db to env
    }

    private fun sha(f: File): String = MessageDigest.getInstance("SHA-256").digest(f.readBytes()).joinToString("") { "%02x".format(it) }

    /** Every file under [dir] by its path below it, with the sum of its bytes: what "nothing in the folder changed" compares. */
    private fun listing(dir: File): Map<String, String> =
        dir.walkTopDown().filter { it.isFile }.associate { it.relativeTo(dir).path to sha(it) }.toSortedMap()

    private fun long(db: File, sql: String): Long = DriverManager.getConnection("jdbc:sqlite:${db.path}").use { c ->
        c.createStatement().use { st -> st.executeQuery(sql).use { rs -> if (rs.next()) rs.getLong(1) else 0L } }
    }

    /** Overwrites the root page of [table] in [db] with zeros: the integrity check then names faults, while other tables stay readable. */
    private fun damage(db: File, table: String) {
        val (pageSize, root) = DriverManager.getConnection("jdbc:sqlite:${db.path}").use { c ->
            c.createStatement().use { st ->
                val ps = st.executeQuery("PRAGMA page_size").use { it.next(); it.getLong(1) }
                val rp = st.executeQuery("SELECT rootpage FROM sqlite_master WHERE name='$table'").use { it.next(); it.getLong(1) }
                ps to rp
            }
        }
        assertTrue(root > 1)
        RandomAccessFile(db, "rw").use { f -> f.seek((root - 1) * pageSize); f.write(ByteArray(pageSize.toInt())) }
    }

    private val wayBack = "copy the backup's andvari.db into place again, then run `andvari admin restored` again; the backup to take is the newest snapshot that passes `PRAGMA integrity_check`"

    @Test fun aDatabaseWithADamagedPageIsRefusedBeforeAnySessionEndsAndTheFolderStaysAsItWas() = world {
        operator()
        account(member("alice")).synced()
        val (db, env) = putBack(takeSnapshot(), "damaged") { dir -> damage(File(dir, "andvari.db"), "audit") }
        val live = long(db, "SELECT COUNT(*) FROM sessions WHERE revokedAt IS NULL")
        val counter = long(db, "SELECT COALESCE(MAX(rev), 0) FROM changes")
        assertTrue(live > 0)
        val before = listing(db.parentFile)
        val r = adminRestored(env)
        assertEquals(1, r.code, "${r.out} ${r.err}")
        assertTrue(r.err.startsWith("andvari: the database ${db.path} could not be read: it did not pass SQLite's integrity check ("), r.err)
        assertTrue("; nothing was changed: do not start the server; $wayBack" in r.err, r.err)
        assertFalse("or run the version of andvari that made" in r.err, r.err)
        assertEquals(1, r.err.trim().lines().size, r.err)
        assertEquals(before, listing(db.parentFile), "the folder, file for file and byte for byte")
        assertEquals(live, long(db, "SELECT COUNT(*) FROM sessions WHERE revokedAt IS NULL"), "no session ended")
        assertEquals(counter, long(db, "SELECT COALESCE(MAX(rev), 0) FROM changes"), "no change counted")
    }

    @Test fun aFileThatIsNoDatabaseIsRefusedByTheCheckWithTheWayBack() = world {
        operator()
        val (db, env) = putBack(takeSnapshot(), "notadb") { dir -> File(dir, "andvari.db").writeText("this is not a database at all, but a text file of some length ".repeat(100)) }
        val before = listing(db.parentFile)
        val r = adminRestored(env)
        assertEquals(1, r.code, "${r.out} ${r.err}")
        assertTrue(r.err.startsWith("andvari: ${db.path} is not an SQLite database ("), r.err)
        assertTrue("; nothing was changed: do not start the server; $wayBack" in r.err, r.err)
        assertFalse("or run the version of andvari that made" in r.err, r.err)
        assertEquals(before, listing(db.parentFile))
    }

    @Test fun anEmptyFileIsRefusedAsEmptyWithTheWayBack() = world {
        operator()
        val (db, env) = putBack(takeSnapshot(), "empty") { dir -> File(dir, "andvari.db").writeBytes(ByteArray(0)) }
        val before = listing(db.parentFile)
        val r = adminRestored(env)
        assertEquals(1, r.code, "${r.out} ${r.err}")
        assertTrue(r.err.startsWith("andvari: the database ${db.path} is empty (0 bytes), so it is no database to restore;"), r.err)
        assertTrue("; nothing was changed: do not start the server; $wayBack" in r.err, r.err)
        assertFalse("or run the version of andvari that made" in r.err, r.err)
        assertEquals(before, listing(db.parentFile))
    }

    /** Every file under [dir] and [dir] itself, by path, with its time of last change: what "the folder's times" compares. */
    private fun times(dir: File): Map<String, Long> =
        dir.walkTopDown().associate { it.relativeTo(dir).path to it.lastModified() }.toSortedMap()

    private fun sql(db: File, vararg statements: String) = DriverManager.getConnection("jdbc:sqlite:${db.path}").use { c ->
        c.createStatement().use { st -> statements.forEach { st.execute(it) } }
    }

    /**
     * A sound SQLite file that is not a database of this server, and a sound andvari database of another build, each with a
     * rollback-journal header and with a write-ahead header: refused in the check's own opening, before anything opens the
     * file for writing, with the way back, and the folder as it was: its names, every file's bytes, and every time, the
     * folder's own included (decided on 22 November 2026).
     */
    @Test fun aSoundDatabaseThatIsNotThisServersIsRefusedBeforeAnyOpenForWriting() = world {
        operator()
        val snapshot = takeSnapshot()
        // Another program's database, made in a folder of its own and copied over the put-back file.
        fun foreign(vararg first: String): (File) -> Unit = { f ->
            val made = File(Files.createTempDirectory(server.dir.toPath(), "foreign").toFile(), "other.db")
            sql(made, *first, "CREATE TABLE t(id INTEGER PRIMARY KEY, v TEXT)", "INSERT INTO t(v) VALUES('another program')")
            Files.copy(made.toPath(), f.toPath(), java.nio.file.StandardCopyOption.REPLACE_EXISTING)
        }
        val cases = listOf(
            Triple("foreignRollback", "none", foreign()),
            Triple("foreignWriteAhead", "none", foreign("PRAGMA journal_mode=WAL")),
            Triple("otherBuildRollback", "'another-build-9'", { f: File -> sql(f, "UPDATE meta SET value='another-build-9' WHERE key='baseline'") }),
            Triple("otherBuildWriteAhead", "'another-build-9'", { f: File -> sql(f, "UPDATE meta SET value='another-build-9' WHERE key='baseline'", "PRAGMA journal_mode=WAL") }),
        )
        for ((label, baseline, make) in cases) {
            val (db, env) = putBack(snapshot, label) { dir -> make(File(dir, "andvari.db")) }
            assertEquals(listOf("andvari.db"), db.parentFile.list()!!.filter { it.startsWith("andvari.db") }, "$label: nothing beside the file")
            assertEquals(label.endsWith("WriteAhead"), io.silencelen.andvari.server.Db.headerSaysWriteAhead(db), "$label: its header")
            // The folder's time is read after a pause, so that a file made and removed beside the database moves it.
            Thread.sleep(1100)
            val bytes = listing(db.parentFile)
            val before = times(db.parentFile)
            val r = adminRestored(env)
            assertEquals(1, r.code, "$label: ${r.out} ${r.err}")
            assertTrue(r.err.startsWith("andvari: the database ${db.path} is not a database of this build (baseline $baseline, this build expects '"), "$label: ${r.err}")
            // The file passes the check, so the way back names a snapshot a server of this build made; a database with another
            // build's marker also names the version that made it, and another program's file does not.
            val otherBuild = baseline != "none"
            assertTrue(
                r.err.trim().endsWith(
                    "; nothing was changed: do not start the server; copy the backup's andvari.db into place again, then run " +
                        "`andvari admin restored` again; the backup to take is the newest snapshot that a server of this build made " +
                        "and that passes `PRAGMA integrity_check`" + (if (otherBuild) ", or run the version of andvari that made this database" else ""),
                ),
                "$label: ${r.err}",
            )
            assertEquals(otherBuild, "or run the version of andvari that made" in r.err, "$label: ${r.err}")
            assertEquals(1, r.err.trim().lines().size, "$label: ${r.err}")
            assertEquals(bytes, listing(db.parentFile), "$label: names and bytes")
            assertEquals(before, times(db.parentFile), "$label: every time, the folder's own included")
        }
    }

    /** A file left beside the database is refused as before, with its own line, whether the database would pass the check or not. */
    @Test fun aFileLeftBesideTheDatabaseIsRefusedAsBeforeAndTheCheckIsNotReached() = world {
        operator()
        account(member("alice")).synced()
        val snapshot = takeSnapshot()
        for ((label, damaged) in listOf("soundBeside" to false, "damagedBeside" to true)) {
            val (db, env) = putBack(snapshot, label) { dir ->
                if (damaged) damage(File(dir, "andvari.db"), "audit")
                File(dir, "andvari.db-shm").writeBytes(ByteArray(32768))
            }
            val before = listing(db.parentFile)
            val r = adminRestored(env)
            assertEquals(1, r.code, "$label: ${r.out} ${r.err}")
            assertTrue(r.err.startsWith("andvari: Left over beside the database: andvari.db-shm."), "$label: ${r.err}")
            assertFalse("integrity check" in r.err, "$label: ${r.err}")
            // Byte for byte as it was: no session ended and no change counted in the database either.
            assertEquals(before, listing(db.parentFile), label)
        }
    }
}
