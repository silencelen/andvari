package io.silencelen.andvari.hostile

import io.silencelen.andvari.cli.e2e.doc
import io.silencelen.andvari.cli.e2e.synced
import io.silencelen.andvari.server.Db
import io.silencelen.andvari.server.HostCli
import io.silencelen.andvari.server.IncompatibleDatabase
import java.io.File
import java.io.RandomAccessFile
import java.nio.file.Files
import java.security.MessageDigest
import java.sql.DriverManager
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The guard before the server's database is opened, on two paths it did not cover: a database path that is a symbolic
 * link whose target does not exist yet (SQLite follows it, creates the database at the target and drops a write-ahead
 * file it finds beside the new, empty file), and the refusals of a database this build may not open (another build's, or
 * one whose settings table cannot be read), which switched a put-back file's journal mode before they decided.
 */
class DatabaseGuardLinksAndRefusalsTest {
    private fun sha(f: File): String =
        if (!f.exists()) "missing" else MessageDigest.getInstance("SHA-256").digest(f.readBytes()).joinToString("") { "%02x".format(it) }

    /** The names in [db]'s folder that begin with its name: the database and the files SQLite keeps beside it. */
    private fun beside(db: File): List<String> = db.absoluteFile.parentFile.list()!!.filter { it.startsWith(db.name) }.sorted()

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

    /** The running server's database file, after forty saves its write-ahead file holds. */
    private suspend fun World.liveWithFortySaves(): File {
        operator()
        val a = account(member("alice"))
        val v = assertNotNull(a.personalVaultId)
        for (i in 1..40) assertNull(a.putItem(v, doc("save $i")).second)
        a.synced()
        val live = File(HostCli.configFrom(server.envFile).dbPath)
        assertTrue(File(live.path + "-wal").length() > 0 && File(live.path + "-shm").exists(), "the running server's write-ahead file")
        return live
    }

    /** Every command of the server's tool that opens the database, each with the least it needs, against [env]. */
    private fun everyCommand(env: File): List<List<String>> = listOf(
        listOf("admin", "status"), listOf("admin", "accounts"), listOf("admin", "operator"), listOf("admin", "audit"),
        listOf("admin", "disable", "bob@example.org"), listOf("admin", "enable", "bob@example.org"),
        listOf("admin", "signup", "open"), listOf("admin", "signup", "cap", "5"),
        listOf("admin", "quota", "--account", "bob@example.org", "--items", "5"),
        listOf("admin", "enrol-link"), listOf("admin", "setup-link"), listOf("admin", "reset-instance-identity"),
        listOf("setup", "--status"), listOf("setup", "--reset-setup"),
    ).map { it + listOf("--env-file", env.path) }

    /** The server's own program in a process of its own, as the image runs it, on [env]: its exit code and what it said. */
    private fun serverStart(env: File): Pair<Int, String> {
        val javaBin = File(System.getProperty("java.home"), "bin/java").path
        val pb = ProcessBuilder(listOf(javaBin, "-cp", System.getProperty("java.class.path"), "io.silencelen.andvari.server.MainKt"))
            .redirectErrorStream(true)
        pb.environment().putAll(HostCli.readEnvFile(env))
        pb.environment()["ANDVARI_PORT"] = java.net.ServerSocket(0).use { it.localPort }.toString()
        val p = pb.start()
        val text = StringBuilder()
        val reader = Thread { text.append(p.inputStream.bufferedReader().readText()) }.apply { start() }
        val ended = p.waitFor(120, TimeUnit.SECONDS)
        if (!ended) p.destroyForcibly().waitFor()
        reader.join(10_000)
        assertTrue(ended, "the server started and kept running: $text")
        return p.exitValue() to text.toString()
    }

    /**
     * The database's path is a symbolic link to a file that does not exist yet, and the replaced database's write-ahead
     * file and its `-shm` lie where that file would be. Until now every command opened the database through the link:
     * SQLite created a new, empty database at the target and deleted the two files. Now every command of the tool, the
     * `restored` command and the server's start refuse before anything is opened, name the link and the file it leads to
     * and the two files; nothing is created and the two files are byte for byte as they were. `andvari setup` with that
     * path is refused in its own words, naming the folder the link leads to.
     */
    @Test fun aLinkWhoseTargetDoesNotExistYetIsRefusedBesideTheFileItLeadsToAndTheLeftoverFilesAreKept() = world {
        val live = liveWithFortySaves()
        val snapshot = takeSnapshot()
        val targetDir = Files.createTempDirectory(server.dir.toPath(), "danglingTarget").toFile()
        Files.copy(File(live.path + "-wal").toPath(), File(targetDir, "andvari.db-wal").toPath())
        Files.copy(File(live.path + "-shm").toPath(), File(targetDir, "andvari.db-shm").toPath())
        val target = File(targetDir, "andvari.db")
        val link = File(Files.createTempDirectory(server.dir.toPath(), "danglingLink").toFile(), "andvari.db")
        Files.createSymbolicLink(link.toPath(), target.toPath())
        assertFalse(link.exists(), "the link's target does not exist")
        val (_, env) = putBack(snapshot, "danglingEnv")
        HostCli.editEnvFile(env, mapOf("ANDVARI_DB" to link.path))
        val two = listOf(File(targetDir, "andvari.db-wal"), File(targetDir, "andvari.db-shm"))
        val shas = two.map { sha(it) }
        val words = "${link.path} is a link to ${File(targetDir.canonicalFile, "andvari.db").path}: the files named here lie beside that file. " +
            "Left over beside the database: andvari.db-wal and andvari.db-shm."

        for (argv in everyCommand(env) + listOf(listOf("admin", "restored", "--env-file", env.path))) {
            val r = hostTool(argv)
            assertEquals(1, r.code, "$argv: ${r.out} ${r.err}")
            assertTrue(r.err.startsWith("andvari: $words"), "$argv: ${r.err}")
            assertTrue(r.err.trim().endsWith("Nothing was changed."), "$argv: ${r.err}")
            assertEquals(1, r.err.trim().lines().size, "$argv: one line, no stack trace: ${r.err}")
            assertEquals(listOf("andvari.db-shm", "andvari.db-wal"), beside(target), "$argv: no database was created at the link's target")
            assertEquals(shas, two.map { sha(it) }, "$argv: the -wal and the -shm are byte for byte as they were")
            assertTrue(Files.isSymbolicLink(link.toPath()), "$argv: the link is still a link")
        }

        val (code, text) = serverStart(env)
        assertEquals(1, code, text)
        val line = text.lines().singleOrNull { "refusing to start" in it } ?: ""
        assertTrue(line.startsWith("[andvari] refusing to start: $words"), text)
        assertFalse("Exception" in text || "\tat " in text, "no stack trace: $text")
        assertEquals(listOf("andvari.db-shm", "andvari.db-wal"), beside(target), "the server's start created no database")
        assertEquals(shas, two.map { sha(it) }, "the server's start: the two files byte for byte")

        val setupDir = Files.createTempDirectory(server.dir.toPath(), "danglingSetup").toFile()
        val setupEnv = File(setupDir, "andvari.env")
        val s = hostTool(listOf("setup", "--origin", "https://example.org", "--env-file", setupEnv.path, "--data-dir", File(setupDir, "data").path, "--db", link.path))
        assertEquals(1, s.code, "${s.out} ${s.err}")
        assertEquals(
            "andvari: andvari.db-wal and andvari.db-shm lie in the data folder ${targetDir.canonicalPath}. Setup makes a new instance only " +
                "in a folder without them: move andvari.db-wal and andvari.db-shm out of this folder and keep them, then run setup again. " +
                "Nothing was created or changed.",
            s.err.trim(),
        )
        assertFalse(setupEnv.exists(), "setup wrote no environment file")
        assertEquals(listOf("andvari.db-shm", "andvari.db-wal"), beside(target), "setup created no database")
        assertEquals(shas, two.map { sha(it) }, "setup: the two files byte for byte")
    }

    /**
     * A healthy first start through a link to a file that does not exist yet, with nothing beside it: the tool's status
     * command creates the new database at the link's target, in write-ahead mode, and the link stays a link. `andvari
     * setup` with such a path is refused in its own words before it creates anything (setup never creates a file or a
     * folder where a link leads); with a link to an existing empty file it makes the instance's database in that file,
     * and the tool then opens it through the link.
     */
    @Test fun aFirstStartThroughALinkToAFileThatDoesNotExistYetWorksAndSetupThroughSuchALinkIsRefused() = world {
        operator()
        val snapshot = takeSnapshot()
        val targetDir = Files.createTempDirectory(server.dir.toPath(), "newTarget").toFile()
        val target = File(targetDir, "andvari.db")
        val link = File(Files.createTempDirectory(server.dir.toPath(), "newLink").toFile(), "andvari.db")
        Files.createSymbolicLink(link.toPath(), target.toPath())
        val (_, env) = putBack(snapshot, "newEnv")
        HostCli.editEnvFile(env, mapOf("ANDVARI_DB" to link.path))
        val st = hostTool(listOf("admin", "status", "--env-file", env.path))
        assertEquals(0, st.code, "${st.out} ${st.err}")
        assertTrue(target.isFile && Db.headerSaysWriteAhead(target), "a new database at the link's target, in write-ahead mode")
        assertTrue(Files.isSymbolicLink(link.toPath()), "the link is still a link")

        val setupTargetDir = Files.createTempDirectory(server.dir.toPath(), "setupTarget").toFile()
        val setupTarget = File(setupTargetDir, "andvari.db")
        val setupLink = File(Files.createTempDirectory(server.dir.toPath(), "setupLink").toFile(), "andvari.db")
        Files.createSymbolicLink(setupLink.toPath(), setupTarget.toPath())
        val setupDir = Files.createTempDirectory(server.dir.toPath(), "setupThroughLink").toFile()
        val setupEnv = File(setupDir, "andvari.env")
        val s = hostTool(listOf("setup", "--origin", "https://example.org", "--env-file", setupEnv.path, "--data-dir", File(setupDir, "data").path, "--db", setupLink.path))
        assertEquals(1, s.code, "${s.out} ${s.err}")
        assertEquals(
            "andvari: ${setupLink.path} is a link to ${File(setupTargetDir.canonicalFile, "andvari.db").path}, which does not exist: setup makes " +
                "the database only at a path that is not a link (or a link to an existing empty file). Nothing was created or changed.",
            s.err.trim(),
        )
        assertEquals(emptyList<String>(), setupTargetDir.list()!!.toList(), "setup created nothing at the link's target")
        assertEquals(emptyList<String>(), setupDir.list()!!.toList(), "setup wrote no environment file and made no data folder")
        assertTrue(Files.isSymbolicLink(setupLink.toPath()), "the link is still a link")

        setupTarget.createNewFile()
        val s2 = hostTool(listOf("setup", "--origin", "https://example.org", "--env-file", setupEnv.path, "--data-dir", File(setupDir, "data").path, "--db", setupLink.path))
        assertEquals(0, s2.code, "${s2.out} ${s2.err}")
        assertTrue(setupTarget.length() > 0, "setup made the database in the existing empty file the link leads to")
        assertTrue(Files.isSymbolicLink(setupLink.toPath()), "the link is still a link")
        assertEquals(setupLink.path, HostCli.configFrom(setupEnv).dbPath, "the environment file names the path setup was given")
        val after = hostTool(listOf("admin", "status", "--env-file", setupEnv.path))
        assertEquals(0, after.code, "${after.out} ${after.err}")
    }

    /**
     * A put-back file (rollback mode) that this build refuses after reading it: one a different build made (another
     * baseline), and one whose settings table cannot be read (its root page overwritten with zeros). Every command of the
     * tool refuses it in one plain line with exit 1, as before; until now each refusal first switched the file's header to
     * write-ahead mode. Now the file is byte for byte as it was, its header still says rollback mode, and nothing lies
     * beside it.
     */
    @Test fun aPutBackFileOfAnotherBuildOrWithAnUnreadableSettingsTableIsRefusedAndLeftByteForByte() = world {
        operator()
        account(member("alice")).synced()
        val snapshot = takeSnapshot()
        val (other, otherEnv) = putBack(snapshot, "otherBuild") { dir ->
            DriverManager.getConnection("jdbc:sqlite:${File(dir, "andvari.db").path}").use { c ->
                c.createStatement().use { it.executeUpdate("UPDATE meta SET value='another-build-9' WHERE key='baseline'") }
            }
        }
        val (corrupt, corruptEnv) = putBack(snapshot, "settingsUnreadable")
        val (pageSize, root) = DriverManager.getConnection("jdbc:sqlite:${corrupt.path}").use { c ->
            c.createStatement().use { st ->
                val ps = st.executeQuery("PRAGMA page_size").use { it.next(); it.getLong(1) }
                val rp = st.executeQuery("SELECT rootpage FROM sqlite_master WHERE name='meta'").use { it.next(); it.getLong(1) }
                ps to rp
            }
        }
        assertTrue(root > 1)
        RandomAccessFile(corrupt, "rw").use { f -> f.seek((root - 1) * pageSize); f.write(ByteArray(pageSize.toInt())) }
        val cases = listOf(
            Triple(other, otherEnv, "andvari: This database was created by a different andvari build (baseline 'another-build-9', this build expects '${Db.BASELINE}')."),
            Triple(corrupt, corruptEnv, "andvari: the database ${corrupt.path} could not be read ("),
        )
        for ((db, env, words) in cases) {
            assertFalse(Db.headerSaysWriteAhead(db), "the put-back file is in rollback mode")
            val sha = sha(db)
            for (argv in everyCommand(env)) {
                val r = hostTool(argv)
                assertEquals(1, r.code, "$argv: ${r.out} ${r.err}")
                assertTrue(r.err.startsWith(words), "$argv: ${r.err}")
                assertEquals(1, r.err.trim().lines().size, "$argv: one line, no stack trace: ${r.err}")
                assertEquals(sha, sha(db), "$argv: the refused file is byte for byte as it was")
                assertFalse(Db.headerSaysWriteAhead(db), "$argv: its header still says rollback mode")
                assertEquals(listOf("andvari.db"), beside(db), "$argv: nothing lies beside it")
            }
        }
    }

    /**
     * A put-back file of another build in rollback mode with a hot journal of its own beside it: copied, with its
     * journal, while its writer was in the middle of a transaction that had already written pages into the file (a writer
     * stopped mid-transaction). The server's own opening refuses it in one line. The read that decides rolls the journal
     * back into the file first, as any opening of the file does: afterwards the journal is gone, the file is whole, and it
     * holds exactly the rows that were committed: the unfinished transaction is undone and no commit is lost.
     */
    @Test fun aRefusedRollbackModeFileWithAHotJournalOfItsOwnHasThatJournalRolledBackAndKeepsEveryCommit() = world {
        operator()
        account(member("alice")).synced()
        val snapshot = takeSnapshot()
        val (source, _) = putBack(snapshot, "hotJournalSource") { dir ->
            DriverManager.getConnection("jdbc:sqlite:${File(dir, "andvari.db").path}").use { c ->
                c.createStatement().use { it.executeUpdate("UPDATE meta SET value='another-build-9' WHERE key='baseline'") }
            }
        }
        assertFalse(Db.headerSaysWriteAhead(source), "the put-back file is in rollback mode")
        fun rows(c: java.sql.Connection): List<String> = c.createStatement().use { st ->
            st.executeQuery("SELECT key || '=' || value FROM meta ORDER BY key").use { rs -> buildList { while (rs.next()) add(rs.getString(1)) } }
        }
        val committed = DriverManager.getConnection("jdbc:sqlite:${source.path}").use { rows(it) }
        val committedLength = source.length()
        val copy = File(Files.createTempDirectory(server.dir.toPath(), "hotJournalCopy").toFile(), "andvari.db")
        DriverManager.getConnection("jdbc:sqlite:${source.path}").use { c ->
            // A small page cache makes the unfinished transaction write its pages into the file, its journal holding the old ones.
            c.createStatement().use { it.execute("PRAGMA cache_size=10") }
            c.autoCommit = false
            c.createStatement().use { st ->
                st.executeUpdate(
                    "INSERT INTO meta(key,value) WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i<3000) " +
                        "SELECT 'unfinished '||i, hex(randomblob(400)) FROM n",
                )
            }
            for (n in listOf("", "-journal")) Files.copy(File(source.path + n).toPath(), File(copy.path + n).toPath())
            c.rollback()
        }
        assertTrue(File(copy.path + "-journal").length() > 0, "a journal of its own lies beside the copy")
        assertTrue(copy.length() > committedLength, "pages of the unfinished transaction were written into the copy")

        val e = assertFailsWith<IncompatibleDatabase> { Db(copy.path).close() }
        assertEquals("This database was created by a different andvari build (baseline 'another-build-9', this build expects '${Db.BASELINE}').", e.message)
        assertEquals(listOf("andvari.db"), beside(copy), "the journal was rolled back into the file and is gone")
        val after = DriverManager.getConnection("jdbc:sqlite:${copy.path}").use { c ->
            c.createStatement().use { st -> st.executeQuery("PRAGMA integrity_check").use { rs -> rs.next(); assertEquals("ok", rs.getString(1)) } }
            rows(c)
        }
        assertEquals(committed, after, "exactly the committed rows: the unfinished transaction is undone and no commit is lost")
    }
}
