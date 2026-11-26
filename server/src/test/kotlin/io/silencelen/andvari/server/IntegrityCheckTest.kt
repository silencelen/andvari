package io.silencelen.andvari.server

import org.sqlite.SQLiteConfig
import java.io.File
import java.io.RandomAccessFile
import java.security.MessageDigest
import java.sql.DriverManager
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue

/**
 * The integrity check both the snapshot command and `andvari admin restored` run ([IntegrityCheck]), and what each way of
 * opening a database does to the files in its folder, in each form the server's database can take: the server's own
 * database in write-ahead mode after a clean stop (no files beside it), the same with its write-ahead file and `-shm`
 * beside it (an unclean stop), and a snapshot, which `VACUUM INTO` writes in rollback mode. Each opening reads the file
 * once; the folder's listing and every file's sum before and after are compared. Only the check's own opening is held to
 * "unchanged"; what the two ordinary openings did is printed, for the record.
 */
class IntegrityCheckTest {
    private fun sha(f: File): String = MessageDigest.getInstance("SHA-256").digest(f.readBytes()).joinToString("") { "%02x".format(it) }

    private fun listing(dir: File): Map<String, String> = dir.listFiles()!!.filter { it.isFile }.associate { it.name to sha(it) }.toSortedMap()

    /** A database in write-ahead mode with a table of 200 rows, closed cleanly (SQLite removes its `-wal` and `-shm`). */
    private fun writeAhead(dir: File): File {
        val db = File(dir, "andvari.db")
        DriverManager.getConnection("jdbc:sqlite:${db.path}").use { c ->
            c.createStatement().use { st ->
                st.execute("PRAGMA journal_mode=WAL")
                st.execute("CREATE TABLE t(id INTEGER PRIMARY KEY, v TEXT)")
                for (i in 1..200) st.execute("INSERT INTO t(v) VALUES('row $i')")
            }
        }
        return db
    }

    /** The three forms, each in a folder of its own. */
    private fun forms(): Map<String, File> {
        val clean = writeAhead(TestKit.tempDir())
        val unclean = writeAhead(TestKit.tempDir()).also { db ->
            File(db.path + "-wal").writeBytes(ByteArray(0))
            File(db.path + "-shm").writeBytes(ByteArray(32768))
        }
        val snapshot = File(TestKit.tempDir(), "andvari.db").also { snap ->
            DriverManager.getConnection("jdbc:sqlite:${clean.path}").use { c -> c.createStatement().use { it.execute("VACUUM INTO '${snap.path}'") } }
        }
        return linkedMapOf("write-ahead, nothing beside" to clean, "write-ahead, -wal and -shm beside" to unclean, "snapshot (rollback mode)" to snapshot)
    }

    private fun readOnce(url: String, props: java.util.Properties = java.util.Properties()) =
        runCatching { DriverManager.getConnection(url, props).use { c -> c.createStatement().use { it.executeQuery("SELECT COUNT(*) FROM sqlite_master").use { rs -> rs.next() } } } }

    @Test
    fun whatEachOpeningDoesToTheFolder_andTheChecksOpeningChangesNothing() {
        for ((form, db) in forms()) {
            val dir = db.parentFile
            val start = listing(dir)
            val readWrite = readOnce("jdbc:sqlite:${db.path}")
            val afterReadWrite = listing(dir)
            println("[$form] before: $start")
            println("[$form] read-write open and one read (${readWrite.exceptionOrNull()?.message ?: "read"}): ${if (afterReadWrite == start) "folder unchanged" else "folder now $afterReadWrite"}")
            val readOnly = readOnce("jdbc:sqlite:${db.path}", SQLiteConfig().apply { setReadOnly(true) }.toProperties())
            val afterReadOnly = listing(dir)
            println("[$form] read-only open and one read (${readOnly.exceptionOrNull()?.message ?: "read"}): ${if (afterReadOnly == afterReadWrite) "folder unchanged" else "folder now $afterReadOnly"}")
            val result = IntegrityCheck.onFileAsItIs(db)
            val afterCheck = listing(dir)
            println("[$form] the check's opening (read only, immutable): ${result::class.simpleName}; ${if (afterCheck == afterReadOnly) "folder unchanged" else "folder now $afterCheck"}")
            assertEquals(afterReadOnly, afterCheck, "$form: the check's opening changed the folder")
        }
    }

    @Test
    fun theCheckJudgesBySQLitesOwnAnswer_andChangesNoFileWhateverItFinds() {
        assertTrue(IntegrityCheck.passed(listOf("ok")))
        assertTrue(!IntegrityCheck.passed(listOf("ok", "ok")) && !IntegrityCheck.passed(emptyList()) && !IntegrityCheck.passed(listOf("*** in database main ***")))

        val sound = writeAhead(TestKit.tempDir())
        assertIs<IntegrityCheck.Result.Passed>(IntegrityCheck.onFileAsItIs(sound))

        val damaged = writeAhead(TestKit.tempDir())
        val (pageSize, root) = DriverManager.getConnection("jdbc:sqlite:${damaged.path}").use { c ->
            c.createStatement().use { st ->
                (st.executeQuery("PRAGMA page_size").use { it.next(); it.getLong(1) }) to
                    (st.executeQuery("SELECT rootpage FROM sqlite_master WHERE name='t'").use { it.next(); it.getLong(1) })
            }
        }
        RandomAccessFile(damaged, "rw").use { f -> f.seek((root - 1) * pageSize); f.write(ByteArray(pageSize.toInt())) }
        val text = File(TestKit.tempDir(), "andvari.db").also { it.writeText("this is not a database at all, but a text file of some length ".repeat(100)) }
        val empty = File(TestKit.tempDir(), "andvari.db").also { it.writeBytes(ByteArray(0)) }
        for (f in listOf(damaged, text, empty)) {
            val before = listing(f.parentFile)
            val r = IntegrityCheck.onFileAsItIs(f)
            println("${f.parentFile.name}: ${r::class.simpleName} ${(r as? IntegrityCheck.Result.Faults)?.answers ?: (r as? IntegrityCheck.Result.Unreadable)?.message ?: ""}")
            assertTrue(r !is IntegrityCheck.Result.Passed, "${f.path}: $r")
            assertEquals(before, listing(f.parentFile), f.path)
        }
        assertIs<IntegrityCheck.Result.Empty>(IntegrityCheck.onFileAsItIs(empty))
    }
}
