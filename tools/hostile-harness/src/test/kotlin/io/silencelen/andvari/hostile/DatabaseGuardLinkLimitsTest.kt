package io.silencelen.andvari.hostile

import io.silencelen.andvari.cli.e2e.doc
import io.silencelen.andvari.cli.e2e.synced
import io.silencelen.andvari.server.Db
import io.silencelen.andvari.server.HostCli
import io.silencelen.andvari.server.IncompatibleDatabase
import java.io.File
import java.nio.file.Files
import java.security.MessageDigest
import java.sql.DriverManager
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Where the guard before the server's database is opened, setup and the `restored` command stop following a database
 * path's links: setup through a link whose target does not exist, a path with more links one after another than the
 * system follows (SQLite follows more, and opens the file at the end), exactly forty and forty-one links, a path the
 * system cannot look at for a plain file where one of its folders should be, and what a refused database in write-ahead
 * mode with its own write-ahead file beside it looks like afterwards.
 */
class DatabaseGuardLinkLimitsTest {
    private fun sha(f: File): String =
        if (!f.exists()) "missing" else MessageDigest.getInstance("SHA-256").digest(f.readBytes()).joinToString("") { "%02x".format(it) }

    /** The names in [db]'s folder that begin with its name: the database and the files SQLite keeps beside it. */
    private fun beside(db: File): List<String> = db.absoluteFile.parentFile.list()!!.filter { it.startsWith(db.name) }.sorted()

    /** Every name in [dir] with what it is: a link and its target, a folder, or the file's hash. */
    private fun folderState(dir: File): Map<String, String> = (dir.list() ?: emptyArray()).sorted().associateWith { n ->
        val p = File(dir, n).toPath()
        when {
            Files.isSymbolicLink(p) -> "link to ${Files.readSymbolicLink(p)}"
            Files.isDirectory(p) -> "folder"
            else -> sha(p.toFile())
        }
    }

    private fun World.newDir(label: String): File = Files.createTempDirectory(server.dir.toPath(), label).toFile()

    /** A copy of [s] put back in a new directory of its own, with an environment file naming it; [extra] runs on the directory first. */
    private fun World.putBack(s: Snapshot, label: String, extra: (File) -> Unit = {}): Pair<File, File> {
        val dir = newDir(label)
        val db = s.db.copyTo(File(dir, "andvari.db"))
        val blobs = File(dir, "blobs").apply { mkdirs() }
        s.blobs.copyRecursively(blobs, overwrite = true)
        extra(dir)
        val env = File(dir, "andvari.env")
        env.writeText(server.envFile.readText())
        HostCli.editEnvFile(env, mapOf("ANDVARI_DB" to db.path, "ANDVARI_BLOB_DIR" to blobs.path))
        return db to env
    }

    private fun setupWords(path: String, tail: String): String =
        "andvari: $path $tail: setup makes the database only at a path that is not a link (or a link to an existing empty file). " +
            "Nothing was created or changed."

    /** Why a path the system could not look at is refused, in the words the operator reads. */
    private val couldNotLookAtIt = "the system could not look at it: a file where one of its folders should be, a folder on the " +
        "way that this user may not search, a symbolic link that cannot be read, or more symbolic links on the way than the system follows"

    /** [n] links one after another, each in a new folder of its own, the first of them to [end]; the last of them. */
    private fun World.fileChain(end: File, label: String, n: Int): File {
        var prev = end
        for (i in 1..n) prev = File(newDir("$label$i"), "andvari.db").also { Files.createSymbolicLink(it.toPath(), prev.toPath()) }
        return prev
    }

    /** [n] folder links one after another, each in a new folder of its own, the first of them to the folder [target]; the last of them. */
    private fun World.folderChain(target: File, label: String, n: Int): File {
        var prev = target
        for (i in 1..n) prev = File(newDir("$label$i"), "d").also { Files.createSymbolicLink(it.toPath(), prev.toPath()) }
        return prev
    }

    /**
     * A snapshot of an instance with one account, and a way to lay the running server's write-ahead file and `-shm`
     * (forty saves made after the snapshot) beside a database in a folder, as the replaced database's files would lie there.
     */
    private suspend fun World.snapshotAndLeftovers(): Pair<Snapshot, (File) -> Unit> {
        operator()
        val a = account(member("alice"))
        val v = assertNotNull(a.personalVaultId)
        a.synced()
        val snapshot = takeSnapshot()
        for (i in 1..40) assertNull(a.putItem(v, doc("after $i")).second)
        a.synced()
        val live = File(HostCli.configFrom(server.envFile).dbPath)
        assertTrue(File(live.path + "-wal").length() > 0, "the running server's write-ahead file")
        return snapshot to { dir: File ->
            Files.copy(File(live.path + "-wal").toPath(), File(dir, "andvari.db-wal").toPath())
            Files.copy(File(live.path + "-shm").toPath(), File(dir, "andvari.db-shm").toPath())
        }
    }

    /**
     * `andvari setup` where the data folder's `andvari.db` is a link to a file in folders that do not exist, outside the
     * data folder. Setup is refused in its own words, naming the link and the file it leads to, before it creates
     * anything: no folder and no file at the link's target, no environment file, and the data folder holds only the link.
     */
    @Test fun setupThroughALinkInTheDataFolderIntoFoldersThatDoNotExistIsRefusedAndCreatesNothing() = world {
        val setupDir = newDir("linkedData")
        val data = File(setupDir, "data").apply { mkdirs() }
        val outsideRoot = newDir("outside")
        val outside = File(outsideRoot, "deep/er/andvari.db")
        val link = File(data, "andvari.db")
        Files.createSymbolicLink(link.toPath(), outside.toPath())
        val env = File(setupDir, "andvari.env")
        val s = hostTool(listOf("setup", "--origin", "https://example.org", "--env-file", env.path, "--data-dir", data.path))
        assertEquals(1, s.code, "${s.out} ${s.err}")
        assertEquals(setupWords(link.path, "is a link to ${File(outside.parentFile.canonicalFile, "andvari.db").path}, which does not exist"), s.err.trim())
        assertEquals(emptyList<String>(), outsideRoot.list()!!.toList(), "no folder was created where the link leads")
        assertEquals(mapOf("andvari.db" to "link to $outside"), folderState(data), "the data folder holds only the link")
        assertFalse(env.exists(), "setup wrote no environment file")
    }

    /**
     * `andvari setup --db` naming a link to a file in folders that do not exist: refused in setup's own words before it
     * creates anything (no folder at the link's target, no data folder, no environment file); the link is still a link.
     */
    @Test fun setupWithADbPathThatLinksIntoFoldersThatDoNotExistIsRefusedAndCreatesNothing() = world {
        val setupDir2 = newDir("linkedDb")
        val outsideRoot2 = newDir("outside2")
        val target2 = File(outsideRoot2, "a/b/andvari.db")
        val link2 = File(setupDir2, "andvari.db")
        Files.createSymbolicLink(link2.toPath(), target2.toPath())
        val env2 = File(setupDir2, "andvari.env")
        val dataDir2 = File(setupDir2, "data")
        val s2 = hostTool(listOf("setup", "--origin", "https://example.org", "--env-file", env2.path, "--db", link2.path, "--data-dir", dataDir2.path))
        assertEquals(1, s2.code, "${s2.out} ${s2.err}")
        assertEquals(setupWords(link2.path, "is a link to ${File(target2.parentFile.canonicalFile, "andvari.db").path}, which does not exist"), s2.err.trim())
        assertEquals(emptyList<String>(), outsideRoot2.list()!!.toList(), "no folder was created where the link leads")
        assertFalse(dataDir2.exists(), "no data folder was created")
        assertFalse(env2.exists(), "setup wrote no environment file")
        assertTrue(Files.isSymbolicLink(link2.toPath()), "the link is still a link")
    }

    /**
     * A database path with more links one after another than the system follows (45): to the put-back file with the
     * replaced database's write-ahead file and `-shm` beside it, to a missing file with those two files beside it, and
     * through 45 folder links on the way to the put-back file. SQLite follows such a chain and opened the file at its
     * end, beside those files; now the guard (the server's own opening and every command), the `restored` command and
     * setup refuse in one line, and the folder at the chain's end is exactly as it was.
     */
    @Test fun aPathWithMoreLinksThanTheSystemFollowsIsRefusedInOneLineAndChangesNothing() = world {
        operator()
        val a = account(member("alice"))
        val v = assertNotNull(a.personalVaultId)
        for (i in 1..3) assertNull(a.putItem(v, doc("before $i")).second)
        a.synced()
        val snapshot = takeSnapshot()
        for (i in 1..40) assertNull(a.putItem(v, doc("after $i")).second)
        a.synced()
        val live = File(HostCli.configFrom(server.envFile).dbPath)
        assertTrue(File(live.path + "-wal").length() > 0, "the running server's write-ahead file")
        fun staleBeside(dir: File) {
            Files.copy(File(live.path + "-wal").toPath(), File(dir, "andvari.db-wal").toPath())
            Files.copy(File(live.path + "-shm").toPath(), File(dir, "andvari.db-shm").toPath())
        }
        fun fileChain(end: File, label: String): File {
            var prev = end
            for (i in 1..45) {
                val l = File(newDir("$label$i"), "andvari.db")
                Files.createSymbolicLink(l.toPath(), prev.toPath())
                prev = l
            }
            return prev
        }

        val (existing, _) = putBack(snapshot, "chainExisting") { staleBeside(it) }
        val missingDir = newDir("chainMissing").also { staleBeside(it) }
        val folderTarget = putBack(snapshot, "chainFolders") { staleBeside(it) }.first.parentFile
        var folder = folderTarget
        for (i in 1..45) {
            val l = File(newDir("folderLink$i"), "d")
            Files.createSymbolicLink(l.toPath(), folder.toPath())
            folder = l
        }
        val cases = listOf(
            Triple("45 links to the put-back file", fileChain(existing, "fileLink"), existing.parentFile),
            Triple("45 links to a missing file", fileChain(File(missingDir, "andvari.db"), "missingLink"), missingDir),
            Triple("45 folder links on the way", File(folder, "andvari.db"), folderTarget),
        )
        val (_, env) = putBack(snapshot, "chainEnv")
        // Each case is checked whole and what failed is said at the end, so that one case's failure hides no other's.
        val failed = cases.mapNotNull { (what, path, end) ->
            runCatching { refusedAndUnchanged(what, path, end, env, couldNotLookAtIt) }.exceptionOrNull()?.let { "$what: ${it.message}" }
        }
        assertEquals(emptyList<String>(), failed)
    }

    /**
     * A database path with a plain file where one of its folders should be (`…/file/andvari.db`): no link lies on the way,
     * and the system cannot look at the path. The guard (the server's own opening and every command), the `restored`
     * command and setup refuse it in the same line as a path with more links on the way than the system follows, and the
     * folder that holds the file is exactly as it was.
     */
    @Test fun aPathWithAPlainFileWhereOneOfItsFoldersShouldBeIsRefusedInTheSameLineAndChangesNothing() = world {
        operator()
        val snapshot = takeSnapshot()
        val base = newDir("fileOnTheWay")
        val file = File(base, "file").apply { writeText("a file, not a folder") }
        val (_, env) = putBack(snapshot, "fileOnTheWayEnv")
        refusedAndUnchanged("a plain file where a folder should be", File(file, "andvari.db"), base, env, couldNotLookAtIt)
    }

    /**
     * Chains past forty that mix links to files and links to folders, 42 links each: 21 links one after another to the
     * put-back file through 21 folder links on the way, and 21 folder links on the way to the first of 21 links one after
     * another to the put-back file. The put-back file has the replaced database's write-ahead file and `-shm` beside it.
     * Each is refused in one line by the guard, the `restored` command and setup, and the folder at its end is unchanged.
     */
    @Test fun aChainThatMixesLinksToFilesAndToFoldersPastFortyIsRefusedInOneLineAndChangesNothing() = world {
        val (snapshot, leftovers) = snapshotAndLeftovers()
        val (first, _) = putBack(snapshot, "mixedFirst") { leftovers(it) }
        val fileLinksThroughFolderLinks = fileChain(File(folderChain(first.parentFile, "mixedFolder", 21), "andvari.db"), "mixedFile", 21)
        val (second, _) = putBack(snapshot, "mixedSecond") { leftovers(it) }
        val lastFileLink = fileChain(second, "mixedTail", 21)
        val folderLinksToFileLinks = File(folderChain(lastFileLink.parentFile, "mixedHead", 21), "andvari.db")
        val (_, env) = putBack(snapshot, "mixedEnv")
        val cases = listOf(
            Triple("21 file links through 21 folder links", fileLinksThroughFolderLinks, first.parentFile),
            Triple("21 folder links to 21 file links", folderLinksToFileLinks, second.parentFile),
        )
        val failed = cases.mapNotNull { (what, path, end) ->
            runCatching { refusedAndUnchanged(what, path, end, env, Db.UNRESOLVED_LINKS) }.exceptionOrNull()?.let { "$what: ${it.message}" }
        }
        assertEquals(emptyList<String>(), failed)
    }

    /**
     * Exactly forty links one after another are followed, as the system follows them: to a put-back file with the
     * replaced database's write-ahead file and `-shm` beside it, the guard refuses in the words that name the link, the
     * file at the chain's end and the two files beside it, and that folder is unchanged; to a file that does not exist
     * yet, with nothing beside it, the database is made at the chain's end. Forty-one links to the put-back file are
     * refused in one line by the guard, the `restored` command and setup, and the folder at the chain's end is unchanged.
     */
    @Test fun fortyLinksOneAfterAnotherAreFollowedAndFortyOneAreRefused() = world {
        val (snapshot, leftovers) = snapshotAndLeftovers()
        val (besideLeftovers, _) = putBack(snapshot, "fortyLeftovers") { leftovers(it) }
        val forty = fileChain(besideLeftovers, "forty", 40)
        val before = folderState(besideLeftovers.parentFile)
        val e = assertFailsWith<IncompatibleDatabase> { Db(forty.path).close() }
        val named = "${forty.path} is a link to ${besideLeftovers.canonicalPath}: the files named here lie beside that file. " +
            "Left over beside the database: andvari.db-wal and andvari.db-shm."
        assertTrue(e.message!!.startsWith(named), e.message)
        assertEquals(before, folderState(besideLeftovers.parentFile), "the folder at the chain's end is exactly as it was")

        val target = File(newDir("fortyNew"), "andvari.db")
        val fortyToNew = fileChain(target, "fortyNew", 40)
        Db(fortyToNew.path).close()
        assertTrue(target.isFile && Db.headerSaysWriteAhead(target), "a new database at the chain's end, in write-ahead mode")
        assertTrue(Files.isSymbolicLink(fortyToNew.toPath()), "the link is still a link")

        val (_, env) = putBack(snapshot, "fortyOneEnv")
        refusedAndUnchanged("41 links to the put-back file", fileChain(besideLeftovers, "fortyOne", 41), besideLeftovers.parentFile, env, Db.UNRESOLVED_LINKS)
    }

    /**
     * [path] is refused, for the reason [why], by the server's own opening, by `admin status` and `admin restored` on
     * [env], and by setup; [end] is unchanged.
     */
    private fun World.refusedAndUnchanged(what: String, path: File, end: File, env: File, why: String) {
        run {
            val before = folderState(end)
            val opening = "could not open the database ${path.path} ($why): check that its folder exists and that its owner and " +
                "permissions let this user open it"
            val e = assertFailsWith<IncompatibleDatabase>(what) { Db(path.path).close() }
            assertEquals(opening, e.message, what)
            assertEquals(before, folderState(end), "$what: the server's own opening changed nothing")

            HostCli.editEnvFile(env, mapOf("ANDVARI_DB" to path.path))
            for (argv in listOf(listOf("admin", "status"), listOf("admin", "restored")).map { it + listOf("--env-file", env.path) }) {
                val r = hostTool(argv)
                assertEquals(1, r.code, "$what $argv: ${r.out} ${r.err}")
                assertEquals("andvari: $opening", r.err.trim(), "$what $argv")
                assertEquals(before, folderState(end), "$what $argv: the folder at the chain's end is exactly as it was")
            }

            val setupDir = newDir("chainSetup")
            val setupEnv = File(setupDir, "andvari.env")
            val s = hostTool(listOf("setup", "--origin", "https://example.org", "--env-file", setupEnv.path, "--db", path.path, "--data-dir", File(setupDir, "data").path))
            assertEquals(1, s.code, "$what setup: ${s.out} ${s.err}")
            assertEquals(
                setupWords(path.path, "could not be followed to a file ($why)"),
                s.err.trim(),
                "$what setup",
            )
            assertEquals(emptyList<String>(), setupDir.list()!!.toList(), "$what setup: nothing was created")
            assertEquals(before, folderState(end), "$what setup: the folder at the chain's end is exactly as it was")
        }
    }

    /**
     * Another build's database in write-ahead mode, copied with its own write-ahead file (holding a commit the file does
     * not) and `-shm` while its writer had it open, as after an unclean stop. The server's own opening and the tool refuse
     * it in one line. A refused database in this state is not left byte for byte: SQLite reads its write-ahead file when
     * the refusal reads the database, and merges it into the file when the refused connection closes. Afterwards only
     * the database lies there, and it holds every row it held with its write-ahead file, the last commit among them.
     */
    @Test fun aRefusedDatabaseInWriteAheadModeWithItsOwnWriteAheadFileHasThatFileMergedIntoItAndKeepsEveryCommit() = world {
        operator()
        account(member("alice")).synced()
        val snapshot = takeSnapshot()
        val (source, _) = putBack(snapshot, "walSource") { dir ->
            DriverManager.getConnection("jdbc:sqlite:${File(dir, "andvari.db").path}").use { c ->
                c.createStatement().use { st ->
                    st.executeUpdate("UPDATE meta SET value='another-build-9' WHERE key='baseline'")
                    st.execute("PRAGMA journal_mode=WAL")
                }
            }
        }
        fun rows(c: java.sql.Connection): List<String> = c.createStatement().use { st ->
            st.executeQuery("SELECT key || '=' || value FROM meta ORDER BY key").use { rs -> buildList { while (rs.next()) add(rs.getString(1)) } }
        }
        val copies = listOf(putBack(snapshot, "walRefusedDb"), putBack(snapshot, "walRefusedTool"))
        val held = DriverManager.getConnection("jdbc:sqlite:${source.path}").use { c ->
            c.createStatement().use { st ->
                st.execute("PRAGMA wal_autocheckpoint=0")
                st.executeUpdate("INSERT INTO meta(key,value) VALUES('last-commit', 'only in the write-ahead file')")
            }
            for ((db, _) in copies) {
                for (n in listOf("", "-wal", "-shm")) {
                    Files.copy(File(source.path + n).toPath(), File(db.path + n).toPath(), java.nio.file.StandardCopyOption.REPLACE_EXISTING)
                }
            }
            rows(c)
        }
        assertTrue("last-commit=only in the write-ahead file" in held)
        val words = "This database was created by a different andvari build (baseline 'another-build-9', this build expects '${Db.BASELINE}')."
        for ((db, _) in copies) {
            assertTrue(Db.headerSaysWriteAhead(db), "the copy is in write-ahead mode")
            assertTrue(File(db.path + "-wal").length() > 0, "its own write-ahead file lies beside it")
        }

        val (byDb, _) = copies[0]
        val e = assertFailsWith<IncompatibleDatabase> { Db(byDb.path).close() }
        assertEquals(words, e.message)
        val (byTool, toolEnv) = copies[1]
        val r = hostTool(listOf("admin", "status", "--env-file", toolEnv.path))
        assertEquals(1, r.code, "${r.out} ${r.err}")
        assertEquals("andvari: $words", r.err.trim())

        for (db in listOf(byDb, byTool)) {
            assertEquals(listOf("andvari.db"), beside(db), "${db.path}: the write-ahead file was merged into the file and is gone")
            val after = DriverManager.getConnection("jdbc:sqlite:${db.path}").use { c ->
                c.createStatement().use { st -> st.executeQuery("PRAGMA integrity_check").use { rs -> rs.next(); assertEquals("ok", rs.getString(1)) } }
                rows(c)
            }
            assertEquals(held, after, "${db.path}: every row it held with its write-ahead file, the last commit among them")
        }
    }
}
