package io.silencelen.andvari.server

import java.io.ByteArrayOutputStream
import java.io.File
import java.io.PrintStream
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.sql.DriverManager
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Two parts of `andvari admin restored`'s check of the put-back file (decided on 22 November 2026): once its exclusive
 * lock is held, the file must still be the one the check read, or the run stops before its first change; and what
 * SQLite answered goes into the refusal's line cut to 300 characters.
 */
class RestoredCheckAndLockTest {
    private class Ran(val code: Int, val out: String, val err: String)

    private fun tool(vararg argv: String): Ran {
        val out = ByteArrayOutputStream()
        val err = ByteArrayOutputStream()
        val before = System.err
        val code = synchronized(System::class.java) {
            System.setErr(PrintStream(err, true))
            try {
                HostCli.run(argv.toList(), PrintStream(out, true)) { null }
            } finally {
                System.setErr(before)
            }
        }
        return Ran(code, out.toString(), err.toString())
    }

    /** A new instance of this build, made by setup: its settings file and its database, nothing beside the database. */
    private fun instance(): Pair<File, File> {
        val dir = TestKit.tempDir()
        val env = File(dir, "andvari.env")
        val data = File(dir, "data")
        assertEquals(0, tool("setup", "--test", "--stop-at-setup", "--env-file", env.path, "--data-dir", data.path).code)
        val db = File(data, "andvari.db")
        assertEquals(listOf("andvari.db"), data.list()!!.filter { it.startsWith("andvari.db") }, "nothing beside the database")
        return env to db
    }

    private fun record(db: File): String? = DriverManager.getConnection("jdbc:sqlite:${db.path}").use { c ->
        c.queryOne("SELECT value FROM meta WHERE key=?", RestoredStart.RECORD_KEY) { it.getString(1) }
    }

    /**
     * The file is replaced by a sound copy of itself after the check passed and before the lock is taken: another file
     * under the same name. The run stops and writes nothing. Without the comparison under the lock it would go on, on a
     * file the check never read, and write its record.
     */
    @Test
    fun aFileReplacedBetweenTheCheckAndTheLockStopsTheRunBeforeItsFirstChange() {
        val (env, db) = instance()
        val copy = File(TestKit.tempDir(), "andvari.db")
        Files.copy(db.toPath(), copy.toPath())
        RestoredStart.betweenCheckAndLock = { Files.move(copy.toPath(), db.toPath(), StandardCopyOption.REPLACE_EXISTING) }
        val r = try {
            tool("admin", "restored", "--env-file", env.path)
        } finally {
            RestoredStart.betweenCheckAndLock = {}
        }
        assertEquals(1, r.code, "${r.out} ${r.err}")
        assertTrue(
            r.err.startsWith("andvari: the database ${db.path} changed between its integrity check and this run (another process wrote to it or replaced it); this run changed nothing in it"),
            r.err,
        )
        assertNull(record(db), "no record of a run: nothing was changed")
        // Unchanged after it, the same file goes through.
        val ok = tool("admin", "restored", "--env-file", env.path)
        assertEquals(0, ok.code, "${ok.out} ${ok.err}")
    }

    /**
     * A database whose two indexes were swapped: SQLite's check answers a fault for every row, each naming an index whose
     * name is 150 characters long. The refusal's line carries the first answers cut to 300 characters and an ellipsis;
     * without the cut it would carry all of them (over 300).
     */
    @Test
    fun whatTheCheckAnsweredIsCutTo300Characters() {
        val (env, db) = instance()
        val faulty = File(TestKit.tempDir(), "faulty.db")
        val i1 = "i" + "a".repeat(148) + "1"
        val i2 = "i" + "a".repeat(148) + "2"
        DriverManager.getConnection("jdbc:sqlite:${faulty.path}").use { c ->
            c.createStatement().use { st ->
                st.execute("CREATE TABLE t1(x INTEGER)")
                st.execute("CREATE TABLE t2(x INTEGER)")
                st.execute("CREATE INDEX $i1 ON t1(x)")
                st.execute("CREATE INDEX $i2 ON t2(x)")
                for (n in 1..20) {
                    st.execute("INSERT INTO t1(x) VALUES($n)")
                    st.execute("INSERT INTO t2(x) VALUES(${n + 1000})")
                }
                val r1 = st.executeQuery("SELECT rootpage FROM sqlite_master WHERE name='$i1'").use { it.next(); it.getLong(1) }
                val r2 = st.executeQuery("SELECT rootpage FROM sqlite_master WHERE name='$i2'").use { it.next(); it.getLong(1) }
                st.execute("PRAGMA writable_schema=ON")
                st.execute("UPDATE sqlite_master SET rootpage=CASE name WHEN '$i1' THEN $r2 ELSE $r1 END WHERE name IN ('$i1','$i2')")
            }
        }
        val answers = DriverManager.getConnection("jdbc:sqlite:${faulty.path}").use { c -> c.queryAll("PRAGMA integrity_check") { it.getString(1) } }
        val whole = answers.take(3).joinToString("; ")
        assertTrue(whole.length > 300, "the first three answers are longer than 300 characters: $whole")
        Files.copy(faulty.toPath(), db.toPath(), StandardCopyOption.REPLACE_EXISTING)
        val r = tool("admin", "restored", "--env-file", env.path)
        assertEquals(1, r.code, "${r.out} ${r.err}")
        // The check read the file and found faults in it: the line says so, not that the file could not be read.
        assertTrue(r.err.startsWith("andvari: the database ${db.path} did not pass SQLite's integrity check, which found faults in it (it answered: "), r.err)
        val said = r.err.substringAfter("which found faults in it (it answered: ").substringBefore("); nothing was changed")
        assertEquals(whole.take(300) + "…", said, r.err)
        assertTrue(
            r.err.trim().endsWith(
                "); nothing was changed: do not start the server; copy the backup's andvari.db into place again, then run " +
                    "`andvari admin restored` again; the backup to take is the newest snapshot that passes `PRAGMA integrity_check`",
            ),
            r.err,
        )
        assertTrue("or run the version of andvari that made" !in r.err, r.err)
    }
}
