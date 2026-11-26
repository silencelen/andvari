package io.silencelen.andvari.server

import io.silencelen.andvari.server.BackupFixture.NIGHT_1
import io.silencelen.andvari.server.BackupFixture.NIGHT_2
import io.silencelen.andvari.server.BackupFixture.NIGHT_3
import io.silencelen.andvari.server.BackupFixture.NIGHT_4
import io.silencelen.andvari.server.BackupFixture.Server
import io.silencelen.andvari.server.BackupFixture.backup
import io.silencelen.andvari.server.BackupFixture.connect
import io.silencelen.andvari.server.BackupFixture.copyAside
import io.silencelen.andvari.server.BackupFixture.exists
import io.silencelen.andvari.server.BackupFixture.header
import io.silencelen.andvari.server.BackupFixture.heldServer
import io.silencelen.andvari.server.BackupFixture.holds
import io.silencelen.andvari.server.BackupFixture.inode
import io.silencelen.andvari.server.BackupFixture.letGo
import io.silencelen.andvari.server.BackupFixture.linkCount
import io.silencelen.andvari.server.BackupFixture.newFolder
import io.silencelen.andvari.server.BackupFixture.rows
import io.silencelen.andvari.server.BackupFixture.server
import io.silencelen.andvari.server.BackupFixture.startRefusal
import io.silencelen.andvari.server.BackupFixture.status
import io.silencelen.andvari.server.BackupFixture.stoppedWriter
import io.silencelen.andvari.server.BackupFixture.tree
import io.silencelen.andvari.server.ServerBackup.Seams
import io.silencelen.andvari.server.ServerBackup.Step
import java.io.File
import java.io.IOException
import java.io.RandomAccessFile
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.nio.file.attribute.PosixFilePermissions
import java.sql.Connection
import java.time.Instant
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * `andvari admin backup [--keep N]`, the nightly snapshot as a command of the server (decided on 2026-11-22).
 *
 * Real in every test: the data folder and the database, made by the product's own setup; the SQLite library and the
 * driver the server uses; the files, links and folders in the backup folder; the server's own `Db` for the sentence a
 * start gives. Stand-ins, named where used: the clock is the server's test clock file (a real seam of the product); a
 * fault that real files cannot be made to give at one step (a rename that fails, an error nobody foresaw) is thrown from
 * the command's step hook; the damage to a snapshot before its check is done by the test, to the real file, from that
 * hook; the free room is the one measured number a test may set; and every run here takes the seam that tells it a
 * running server holds the database ([BackupFixture.HELD]), since a running server is a process of its own and these
 * runs are in this process. So every server folder here is made with its database held open from the start by a
 * connection of the fixture that stands in for the running server's own ([BackupFixture.heldServer]), except where the
 * story moves the database or names it by a link: there the first run holds it, through the name the story then uses
 * ([BackupFixture.backup]). Where the story's server is the test's own [Db], the fixture's connection is let go first
 * ([BackupFixture.letGo]). The look at the server itself, beside the server's real start, is in [ServerBackupLookTest];
 * a second process is in [ServerBackupProcessTest].
 */
class ServerBackupTest {
    private val stamp = DateTimeFormatter.ofPattern("uuuu-MM-dd-HHmmss").withZone(ZoneOffset.UTC)
    private val snapshotNames = setOf(ServerBackup.NIGHTLY, ServerBackup.TEMPORARY, "${ServerBackup.TEMPORARY}-journal", "${ServerBackup.TEMPORARY}-wal", "${ServerBackup.TEMPORARY}-shm")

    private fun assertStoppedAt(step: Step, line: String?): String {
        assertNotNull(line, "the run was expected to fail at ${step.words}")
        assertTrue(line.startsWith("backup stopped at ${step.words}: "), "the line names the step ${step.words}: $line")
        assertFalse(line.contains('\n') || line.contains('\r'), "one line: $line")
        return line
    }

    private fun temporaryFamily(s: Server) = listOf("", "-journal", "-wal", "-shm").map { File(s.temporary.path + it) }

    private fun assertNoTemporary(s: Server) = temporaryFamily(s).forEach { assertFalse(exists(it), "${it.name} is left") }

    /** A second connection that holds the database open, as the running server does, with a committed write still in its write-ahead file. */
    private fun heldOpen(s: Server, value: String): Connection = connect(s.db).also { c ->
        c.queryOne("PRAGMA wal_autocheckpoint=0") { it.getString(1) }
        c.exec("INSERT INTO meta(key,value) VALUES(?,?)", "held-open", value)
        check(File(s.db.path + "-wal").length() > 0) { "the write is in the write-ahead file" }
    }

    /** [from] and the files beside it put in place as [to] and its files (each written over), as an operator's copy does. */
    private fun place(from: File, to: File) {
        for (suffix in listOf("", "-wal", "-shm", "-journal")) {
            val src = File(from.path + suffix)
            if (exists(src)) Files.copy(src.toPath(), File(to.path + suffix).toPath(), StandardCopyOption.REPLACE_EXISTING)
        }
    }

    /** A copy of the database [f] in rollback mode, as every snapshot is when it is put back. */
    private fun rollbackCopy(f: File): File = copyAside(f).also { c -> connect(c).use { it.queryOne("PRAGMA journal_mode=DELETE") { r -> r.getString(1) } } }

    // ---------------------------------------------------------------------------------------------------------------
    // A good night
    // ---------------------------------------------------------------------------------------------------------------

    /** Tonight's snapshot under its dated name and the nightly name, one checked file, nothing printed. */
    @Test
    fun aGoodNight_givesOneCheckedSnapshotItsTwoNames_andPrintsNothing() {
        val s = heldServer()
        assertNull(backup(s))
        val dated = s.dated(NIGHT_1)
        assertEquals("andvari-nightly-${stamp.format(Instant.ofEpochMilli(NIGHT_1))}.db", dated.name)
        assertTrue(ServerBackup.DATED.matches(dated.name))
        assertEquals(inode(s.nightly), inode(dated), "one file under two names")
        assertEquals(2, linkCount(s.nightly))
        assertEquals("rw-------", PosixFilePermissions.toString(Files.getPosixFilePermissions(s.nightly.toPath())))
        assertEquals(setOf(ServerBackup.LOCK, ServerBackup.NIGHTLY, dated.name), s.backup.list()!!.toSet())
        assertEquals("rwx------", PosixFilePermissions.toString(Files.getPosixFilePermissions(s.backup.toPath())))
        assertEquals(rows(copyAside(s.db)), rows(copyAside(s.nightly)), "the snapshot holds what the database holds")
        connect(copyAside(s.nightly)).use { c ->
            assertEquals(listOf("ok"), c.queryAll("PRAGMA integrity_check") { it.getString(1) })
            assertEquals(Db.BASELINE, c.queryOne("SELECT value FROM meta WHERE key='baseline'") { it.getString(1) })
        }
        assertEquals(0, status(s.also { it.at(NIGHT_2) }), "the host's command line ends a good run with status 0")
    }

    // ---------------------------------------------------------------------------------------------------------------
    // It decides as the server decides
    // ---------------------------------------------------------------------------------------------------------------

    /** A database without this build's marker, or with another build's, is refused with the start's own sentence. */
    @Test
    fun aDatabaseTheServerRefuses_isRefusedWithTheStartsSentence_andTheBackupFolderStaysAsItWas() {
        for ((what, change) in listOf(
            "no marker" to "DELETE FROM meta WHERE key='baseline'",
            "another marker" to "UPDATE meta SET value='another-build-7' WHERE key='baseline'",
        )) {
            val s = heldServer()
            assertNull(backup(s))
            val before = tree(s.backup)
            connect(s.db).use { it.exec(change) }
            val sentence = assertNotNull(startRefusal(s.db), "$what: the server's start refuses it")
            val bytes = s.db.readBytes().toList()
            s.at(NIGHT_2)
            val line = assertStoppedAt(Step.DATABASE, backup(s))
            assertTrue(line.contains(sentence), "$what: the start's sentence ($sentence) in: $line")
            assertEquals(before, tree(s.backup), "$what: nothing in the backup folder changed")
            assertEquals(bytes, s.db.readBytes().toList(), "$what: the database's bytes are as they were")
            assertEquals(1, status(s), "$what: status 1")
        }
    }

    /**
     * A put-back snapshot (rollback mode) with the replaced database's write-ahead file still beside it, which the
     * server's start refuses. The run refuses before anything opens the file, with the one plain line of a header that does
     * not say write-ahead mode; the put-back file and the write-ahead file keep their bytes, and the snapshots are
     * untouched.
     */
    @Test
    fun aRunBesideAPutBackSnapshotAndTheReplacedDatabasesWriteAheadFile_isRefused_andChangesNoByte() {
        val s = heldServer()
        assertNull(backup(s))
        val putBack = rollbackCopy(s.db)
        val replaced = heldOpen(s, "a save of the replaced database")
        val replacedFiles = copyAside(s.db)
        replaced.close()
        place(putBack, s.db)
        Files.copy(File(replacedFiles.path + "-wal").toPath(), File(s.db.path + "-wal").toPath(), StandardCopyOption.REPLACE_EXISTING)
        Files.copy(File(replacedFiles.path + "-shm").toPath(), File(s.db.path + "-shm").toPath(), StandardCopyOption.REPLACE_EXISTING)
        assertEquals("header 1/1", header(s.db))
        assertNotNull(startRefusal(s.db), "the server's start refuses it")
        s.at(NIGHT_2)
        val data = tree(s.data)
        val line = assertStoppedAt(Step.DATABASE, backup(s))
        assertEquals(data, tree(s.data), "the put-back file, the write-ahead file beside it and every snapshot keep their bytes")
        assertEquals(1, status(s))
        assertEquals(notWriteAheadHeader(s.db.path), line)
    }

    /** The files that lie beside the database [f], of `-wal`, `-shm` and `-journal`. */
    private fun beside(f: File): List<String> = listOf("-wal", "-shm", "-journal").filter { exists(File(f.path + it)) }

    /** An open of a copy of the database [f] and the files beside it applies the journal there, which is then gone. */
    private fun assertAnOpenAppliesTheJournal(f: File) {
        val copy = copyAside(f)
        assertTrue(exists(File(copy.path + "-journal")))
        connect(copy).use { c -> c.queryOne("SELECT count(*) FROM meta") { it.getInt(1) } }
        assertFalse(exists(File(copy.path + "-journal")), "an open of the database applies the journal beside it")
    }

    /**
     * The command's line beside a rollback journal of the database file named [name] whose header says write-ahead mode,
     * word for word.
     */
    private fun writeAheadLine(name: String) =
        "backup stopped at the database: $name-journal lies beside the database. The database file's header says " +
            "write-ahead mode, the mode the server keeps it in. The first open of the database after the server has " +
            "stopped, the server's own next start included, can apply that file to the database, so this command does not " +
            "open it. No snapshot was taken, and nothing was changed. Move this file out of the data folder and keep it, " +
            "before the server is stopped or started; then run this command again."

    /** The command's one line where the header of the database file [named] does not say write-ahead mode, word for word. */
    private fun notWriteAheadHeader(named: String) =
        "backup stopped at the database: the header of the database file $named does not say write-ahead mode. No snapshot " +
            "was taken, and nothing was changed."

    /** How many of the saves named [keys] the database [f] holds, read through the real library. */
    private fun saves(f: File, vararg keys: String): Int =
        connect(f).use { c -> keys.count { k -> c.queryOne("SELECT count(*) FROM meta WHERE key=?", k) { it.getInt(1) } == 1 } }

    /** The main file [f] alone, copied into a folder of its own: nothing that lies beside it is copied. */
    private fun mainFileAlone(f: File): File = File(newFolder("main-file-alone"), f.name).also { Files.copy(f.toPath(), it.toPath()) }

    /**
     * Where the header of the database file does not say write-ahead mode, with a rollback journal beside it or none, the
     * run is refused at the database with one plain line, before anything opens the database (the server holds its
     * database in write-ahead mode from its start). The states: a snapshot of the command's own making put back as the
     * database, alone, with its own journal (a writer in rollback mode stopped inside its transaction) and with another
     * database's; a file that is no database, alone and with a journal; a file shorter than a header (the first 19 bytes
     * of a database in write-ahead mode: every byte the header's mode needs but the last) with a journal; and an empty
     * file. Each keeps every byte, and so does every file beside it and in the backup folder; an open of a copy shows
     * what the run did not do.
     */
    @Test
    fun aDatabaseWhoseHeaderDoesNotSayWriteAheadMode_journalOrNone_isRefusedWithOnePlainLine_andChangesNoByte() {
        val other = heldServer()
        assertNull(backup(other))
        val foreign = File(stoppedWriter(other.nightly).path + "-journal")
        val noDatabase = "this is not an SQLite database. ".repeat(200).encodeToByteArray()
        val states = listOf<Pair<String, (Server) -> Unit>>(
            "a put-back snapshot alone" to { s -> place(rollbackCopy(s.nightly), s.db) },
            "a put-back snapshot with its own journal" to { s -> place(stoppedWriter(s.nightly).also { assertAnOpenAppliesTheJournal(it) }, s.db) },
            "a put-back snapshot with another database's journal" to { s ->
                place(rollbackCopy(s.nightly), s.db)
                Files.copy(foreign.toPath(), File(s.db.path + "-journal").toPath())
                assertAnOpenAppliesTheJournal(s.db)
            },
            "a file that is no database" to { s -> s.db.writeBytes(noDatabase) },
            "a file that is no database with a journal" to { s ->
                s.db.writeBytes(noDatabase)
                Files.copy(foreign.toPath(), File(s.db.path + "-journal").toPath())
            },
            "a file shorter than a header with a journal" to { s ->
                val bytes = s.db.readBytes().copyOf(19)
                assertEquals(listOf(19, 2), listOf(bytes.size, bytes[18].toInt()), "19 bytes, byte 18 as write-ahead mode writes it")
                s.db.writeBytes(bytes)
                Files.copy(foreign.toPath(), File(s.db.path + "-journal").toPath())
            },
            "an empty file" to { s -> s.db.writeBytes(ByteArray(0)) },
        )
        for ((what, make) in states) {
            val s = heldServer()
            assertNull(backup(s), what)
            make(s)
            assertFalse(Db.headerSaysWriteAhead(s.db), what)
            s.at(NIGHT_2)
            val data = tree(s.data)
            val line = assertStoppedAt(Step.DATABASE, backup(s))
            assertEquals(data, tree(s.data), "$what: the database, every file beside it and every snapshot keep their bytes; nothing is made")
            assertEquals(1, status(s), what)
            assertEquals(data, tree(s.data), "$what: the second run changes nothing either")
            assertEquals(notWriteAheadHeader(s.db.path), line, what)
        }
    }

    /** The two rollback journals the fixture makes, for the server folder [s] (whose nightly snapshot exists). */
    private fun journals(s: Server): Map<String, File> {
        val other = heldServer()
        assertNull(backup(other))
        return mapOf(
            "the database's own" to File(stoppedWriter(s.nightly).path + "-journal"),
            "another database's" to File(stoppedWriter(other.nightly).path + "-journal"),
        )
    }

    /**
     * What the library does with a rollback journal beside a database that the server's own [Db] holds open in
     * write-ahead mode and writes on: a new connection's first read is refused (the journal would have to be applied,
     * which needs the whole file to itself), the journal and the file stay as they were, and the server's connection
     * reads and writes on. Once the journal is moved out of the folder, the server writes on and a run works.
     */
    @Test
    fun aJournalBesideADatabaseTheServerHoldsOpen_isNotAppliedWhileItIsHeld_andMovingItOutChangesNothing() {
        for (kind in listOf("the database's own", "another database's")) {
            val s = heldServer()
            assertNull(backup(s))
            val journal = journals(s).getValue(kind)
            val placed = File(s.db.path + "-journal")
            Db(s.db.path).use { running ->
                running.tx { c -> c.exec("INSERT INTO meta(key,value) VALUES(?,?)", "before the journal", "a save") }
                Files.copy(journal.toPath(), placed.toPath())
                val file = s.db.readBytes()
                val first = runCatching { connect(s.db).use { c -> c.queryOne("SELECT count(*) FROM meta") { it.getInt(1) } } }
                val held = runCatching {
                    running.tx { c -> c.exec("INSERT INTO meta(key,value) VALUES(?,?)", "after the new connection", "a save") }
                    running.read { c -> c.queryOne("SELECT count(*) FROM meta WHERE key IN ('before the journal','after the new connection')") { it.getInt(1) } }
                }
                assertEquals(listOf("-wal", "-shm", "-journal"), beside(s.db), kind)
                assertTrue(first.exceptionOrNull()?.message.orEmpty().contains("SQLITE_BUSY"), "$kind: ${first.exceptionOrNull()}")
                assertEquals(2, held.getOrNull(), "$kind: ${held.exceptionOrNull()}")
                assertTrue(placed.readBytes().contentEquals(journal.readBytes()), "$kind: the journal is as it was")
                assertTrue(s.db.readBytes().contentEquals(file), "$kind: the file is as it was")

                Files.move(placed.toPath(), File(newFolder("journal-kept"), placed.name).toPath())
                running.tx { c -> c.exec("INSERT INTO meta(key,value) VALUES(?,?)", "after the journal was moved out", "a save") }
                assertEquals(3, running.read { c -> c.queryOne("SELECT count(*) FROM meta WHERE key IN ('before the journal','after the new connection','after the journal was moved out')") { it.getInt(1) } })
                s.at(NIGHT_2)
                assertNull(backup(s), kind)
                assertTrue(rows(copyAside(s.nightly)).any { it.contains("after the journal was moved out") }, "$kind: the snapshot holds the server's rows")
            }
        }
    }

    /**
     * The state the guide's snapshot line runs in: the server holds the database open in write-ahead mode and writes; a
     * rollback journal lies beside it. The run refuses with the command's own line (status 1 from the command line too),
     * the journal keeps its bytes, nothing new is in the backup folder, and the server writes and reads on; once the
     * journal is moved out of the folder, the run works.
     */
    @Test
    fun aJournalBesideTheRunningServersDatabase_isRefusedWithTheCommandsLine_andTheServerWritesOn() {
        for (kind in listOf("the database's own", "another database's")) {
            val s = heldServer()
            assertNull(backup(s))
            val journal = journals(s).getValue(kind)
            val placed = File(s.db.path + "-journal")
            Db(s.db.path).use { running ->
                running.tx { c -> c.exec("INSERT INTO meta(key,value) VALUES(?,?)", "a save of the running server", "1") }
                Files.copy(journal.toPath(), placed.toPath())
                assertEquals("header 2/2", header(s.db), kind)
                assertEquals(listOf("-wal", "-shm", "-journal"), beside(s.db), kind)
                s.at(NIGHT_2)
                val data = tree(s.data)
                val line = assertStoppedAt(Step.DATABASE, backup(s))
                assertEquals(1, status(s), kind)
                assertEquals(data, tree(s.data), "$kind: the database, its write-ahead file, the journal and the backup folder keep every byte")
                assertTrue(placed.readBytes().contentEquals(journal.readBytes()), "$kind: the journal keeps its bytes")
                running.tx { c -> c.exec("INSERT INTO meta(key,value) VALUES(?,?)", "a save after the refusal", "2") }
                assertEquals(2, running.read { c -> c.queryOne("SELECT count(*) FROM meta WHERE key IN ('a save of the running server','a save after the refusal')") { it.getInt(1) } })

                // The line's instruction followed: the file moved out while the server runs; the run then works.
                Files.move(placed.toPath(), File(newFolder("journal-kept"), placed.name).toPath())
                assertNull(backup(s), kind)
                assertEquals(2, saves(copyAside(s.nightly), "a save of the running server", "a save after the refusal"), kind)
                assertEquals(writeAheadLine(s.db.name), line, kind)
            }
        }
    }

    /**
     * A server (the product's own [Db]) that saved, had a rollback journal of [kind] put beside its database while it ran,
     * saved again, and was then stopped cleanly; the journal is still there.
     */
    private fun stoppedBesideAStrayJournal(kind: String): Server {
        val s = heldServer()
        assertNull(backup(s))
        val journal = journals(s).getValue(kind)
        letGo(s)
        Db(s.db.path).use { running ->
            running.tx { c -> c.exec("INSERT INTO meta(key,value) VALUES(?,?)", "saved before the journal", "1") }
            Files.copy(journal.toPath(), File(s.db.path + "-journal").toPath())
            running.tx { c -> c.exec("INSERT INTO meta(key,value) VALUES(?,?)", "saved after the journal", "2") }
        }
        return s
    }

    private val bothSaves = arrayOf("saved before the journal", "saved after the journal")

    /** What the server's next start (the product's own [Db]) gave on [f]: the number of both saves, or its failure's message. */
    private fun nextStart(f: File): String = runCatching {
        Db(f.path).use { d -> d.read { c -> c.queryOne("SELECT count(*) FROM meta WHERE key IN ('saved before the journal','saved after the journal')") { it.getInt(1) } } }
    }.fold({ "opened, with $it of the two saves" }, { it.message ?: it.toString() })

    /**
     * The state of [stoppedBesideAStrayJournal]: the header still says write-ahead mode, no write-ahead file is left, and
     * the main file alone holds every save. The run refuses with the line of a write-ahead header and changes no byte.
     * Then, on a copy of the folder's files, the instruction not followed: the server's next start applies the journal and
     * finds the database malformed, and the journal is gone. Then the instruction followed: the journal moved out, a run
     * gives a snapshot with every save, and the database opens with every save.
     */
    @Test
    fun aStrayJournalBesideTheDatabaseOfAServerThatThenStoppedCleanly_theLineSaysMoveItOut_andMovingItOutKeepsEverySave() {
        for (kind in listOf("the database's own", "another database's")) {
            val s = stoppedBesideAStrayJournal(kind)
            val placed = File(s.db.path + "-journal")
            assertEquals("header 2/2", header(s.db), kind)
            assertEquals(listOf("-journal"), beside(s.db), "$kind: no write-ahead file is left after the clean stop")
            assertEquals(2, saves(mainFileAlone(s.db), *bothSaves), "$kind: the main file alone holds every save")
            s.at(NIGHT_2)
            val data = tree(s.data)
            val line = assertStoppedAt(Step.DATABASE, backup(s))
            assertEquals(1, status(s), kind)
            assertEquals(data, tree(s.data), "$kind: the database, the journal and the backup folder keep every byte")

            // Not followed: the server's next start, on a copy of the database and the journal beside it.
            val notFollowed = copyAside(s.db)
            val before = notFollowed.readBytes()
            assertEquals("[SQLITE_CORRUPT] The database disk image is malformed (database disk image is malformed)", nextStart(notFollowed), kind)
            assertFalse(exists(File(notFollowed.path + "-journal")), "$kind: the next start applied the journal, which is gone")
            assertFalse(notFollowed.readBytes().contentEquals(before), "$kind: and wrote it into the database")

            // Followed: the journal moved out of the data folder and kept.
            val kept = File(newFolder("journal-kept"), placed.name)
            Files.move(placed.toPath(), kept.toPath())
            assertNull(backup(s), kind)
            assertEquals(2, saves(copyAside(s.nightly), *bothSaves), "$kind: the snapshot holds every save")
            letGo(s)
            assertEquals("opened, with 2 of the two saves", nextStart(s.db), kind)
            connect(copyAside(s.db)).use { c -> assertEquals(listOf("ok"), c.queryAll("PRAGMA integrity_check") { it.getString(1) }, kind) }
            assertEquals(writeAheadLine(s.db.name), line, kind)
        }
    }

    /**
     * A server killed with a committed save still in its write-ahead file, and a stray rollback journal beside the
     * database: the header says write-ahead mode, the line is that of a write-ahead header, and no byte changes. Not
     * followed (on a copy): what the server's next start does. Followed: the database opens with its write-ahead file's
     * save, and a run gives a snapshot that holds it.
     */
    @Test
    fun aStrayJournalBesideTheDatabaseOfAKilledServer_theLineSaysMoveItOut_andMovingItOutKeepsTheSave() {
        for (kind in listOf("the database's own", "another database's")) {
            val s = heldServer()
            assertNull(backup(s))
            val journal = journals(s).getValue(kind)
            val live = connect(s.db).also { c ->
                c.queryOne("PRAGMA wal_autocheckpoint=0") { it.getString(1) }
                c.exec("INSERT INTO meta(key,value) VALUES(?,?)", "saved before the journal", "1")
            }
            val image = copyAside(s.db)
            live.close()
            place(image, s.db)
            Files.copy(journal.toPath(), File(s.db.path + "-journal").toPath())
            assertEquals("header 2/2", header(s.db), kind)
            assertEquals(listOf("-wal", "-shm", "-journal"), beside(s.db), kind)
            assertTrue(File(s.db.path + "-wal").length() > 0, "$kind: the write-ahead file holds the save")
            s.at(NIGHT_2)
            val data = tree(s.data)
            val line = assertStoppedAt(Step.DATABASE, backup(s))
            assertEquals(data, tree(s.data), "$kind: every file keeps its bytes")

            val notFollowed = copyAside(s.db)
            assertEquals("[SQLITE_CORRUPT] The database disk image is malformed (database disk image is malformed)", nextStart(notFollowed), "$kind: not followed")
            assertFalse(exists(File(notFollowed.path + "-journal")), "$kind: the next start applied the journal, which is gone")

            Files.move(File(s.db.path + "-journal").toPath(), File(newFolder("journal-kept"), "${s.db.name}-journal").toPath())
            assertEquals("opened, with 1 of the two saves", nextStart(copyAside(s.db)), "$kind: followed")
            assertNull(backup(s), kind)
            assertEquals(1, saves(copyAside(s.nightly), "saved before the journal"), "$kind: the snapshot holds the save")
            assertEquals(writeAheadLine(s.db.name), line, kind)
        }
    }

    /** A data folder without a database gets no database and no backup folder. */
    @Test
    fun aDataFolderWithoutADatabase_getsNoDatabaseAndNoBackupFolder() {
        val s = heldServer()
        val empty = newFolder("empty-data")
        HostCli.editEnvFile(s.env, mapOf("ANDVARI_DB" to File(empty, "andvari.db").path))
        assertStoppedAt(Step.DATABASE, backup(s))
        assertEquals(emptyList(), empty.list()!!.toList(), "no database and no backup folder")
        assertFalse(exists(s.backup))
        assertEquals(1, status(s))
    }

    /** A file that is not a database is refused, as it is, and no backup folder is made. */
    @Test
    fun aFileThatIsNotADatabase_isRefused_andStaysAsItWas() {
        val s = heldServer()
        s.db.writeText("this is not an SQLite database. ".repeat(200))
        val bytes = s.db.readBytes().toList()
        assertStoppedAt(Step.DATABASE, backup(s))
        assertEquals(bytes, s.db.readBytes().toList())
        assertFalse(exists(s.backup))
        assertEquals(1, status(s))
    }

    // ---------------------------------------------------------------------------------------------------------------
    // It changes nothing of what the database holds
    // ---------------------------------------------------------------------------------------------------------------

    /**
     * Stopped cleanly: in write-ahead mode as the server leaves it, a snapshot; in rollback mode as a put-back snapshot is,
     * refused at the database (the header rule), and the database is as it was.
     */
    @Test
    fun whatTheDatabaseHolds_isUnchanged_whenTheServerStoppedCleanly() {
        val s = heldServer()
        val before = holds(copyAside(s.db))
        assertEquals("header 2/2", before.first())
        assertNull(backup(s))
        assertEquals(before, holds(s.db), "write-ahead mode, stopped cleanly")

        val r = heldServer()
        place(rollbackCopy(r.db), r.db)
        val rollback = holds(copyAside(r.db))
        assertEquals("header 1/1", rollback.first())
        assertEquals(notWriteAheadHeader(r.db.path), backup(r))
        assertEquals(rollback, holds(r.db), "rollback mode: no change of the journal mode, no row, no table")
    }

    /** Stopped uncleanly: the database's own write-ahead file lies beside it, holding a committed save. */
    @Test
    fun whatTheDatabaseHolds_isUnchanged_whenTheServerStoppedUncleanly() {
        val s = heldServer()
        val live = heldOpen(s, "a save the server committed before it was killed")
        val image = copyAside(s.db)
        live.close()
        place(image, s.db)
        assertTrue(File(s.db.path + "-wal").length() > 0, "an unclean stop: the write-ahead file holds the save")
        val before = holds(copyAside(s.db))
        assertNull(backup(s))
        assertEquals(before, holds(s.db))
        assertTrue(rows(copyAside(s.nightly)).any { it.contains("a save the server committed before it was killed") }, "the snapshot holds the save")
    }

    /** Held open by a second connection (the running server) that has committed a write; that connection writes on. */
    @Test
    fun whatTheDatabaseHolds_isUnchanged_whileASecondConnectionHoldsItOpenWithACommittedWrite() {
        val s = heldServer()
        heldOpen(s, "a save of the running server").use { live ->
            val before = holds(copyAside(s.db))
            assertNull(backup(s))
            assertEquals(before, holds(copyAside(s.db)))
            assertTrue(rows(copyAside(s.nightly)).any { it.contains("a save of the running server") }, "the snapshot holds the committed write")
            assertEquals(1, live.exec("INSERT INTO meta(key,value) VALUES('after','the server writes on')"))
        }
    }

    // ---------------------------------------------------------------------------------------------------------------
    // Written under a temporary name, checked, then named; a failed run removes its temporary file
    // ---------------------------------------------------------------------------------------------------------------

    /**
     * A snapshot that fails its check gets neither name, and its temporary file is removed. Stand-in: the damage
     * is done by the test, to the real temporary file, from the hook at the step of the snapshot's check (empty; a damaged page; a
     * database without this build's marker).
     */
    @Test
    fun aSnapshotThatFailsItsCheck_getsNoName_andItsTemporaryFileIsRemoved() {
        // Each damage with what the line says of it: each part of the check is the one that catches its damage.
        val damages = listOf<Triple<String, String, (File) -> Unit>>(
            Triple("empty", "is empty") { f -> RandomAccessFile(f, "rw").use { it.setLength(0) } },
            // The header's count of free pages (bytes 36 to 39) made wrong: every table still reads, the integrity check says no.
            Triple("a wrong count of free pages", "did not pass the integrity check") { f -> RandomAccessFile(f, "rw").use { it.seek(36); it.writeInt(5) } },
            Triple("a damaged page", "could not be read for its check") { f -> RandomAccessFile(f, "rw").use { it.seek(4096); it.write(ByteArray(4096) { 0x55 }) } },
            Triple("no marker", "does not hold this build's marker") { f -> connect(f).use { it.exec("DELETE FROM meta WHERE key='baseline'") } },
        )
        for ((what, said, damage) in damages) {
            val s = heldServer()
            assertNull(backup(s))
            val nightly = s.nightly.readBytes().toList()
            val nightlyInode = inode(s.nightly)
            s.at(NIGHT_2)
            val line = assertStoppedAt(Step.CHECK, backup(s, seams = Seams(serverHolds = true,atStep = { if (it == Step.CHECK) damage(s.temporary) })))
            assertTrue(line.contains(said) && line.contains("no earlier snapshot was changed"), "$what: '$said' in: $line")
            assertFalse(exists(s.dated(NIGHT_2)), "$what: no dated name")
            assertEquals(nightlyInode, inode(s.nightly), "$what: the nightly name is last night's")
            assertEquals(nightly, s.nightly.readBytes().toList(), what)
            assertNoTemporary(s)
        }
    }

    /**
     * The nightly name's step fails after the dated name was given: a failure, and the line says which names
     * exist. Stand-in: the failure is thrown from the hook at the nightly name's step (a rename real files cannot be
     * made to refuse there, after the checks that come before it).
     */
    @Test
    fun whenTheNightlyNameFailsAfterTheDatedName_theLineSaysWhichNamesExist() {
        val s = heldServer()
        assertNull(backup(s))
        val nightlyInode = inode(s.nightly)
        s.at(NIGHT_2)
        val line = assertStoppedAt(Step.NIGHTLY, backup(s, seams = Seams(serverHolds = true,atStep = { if (it == Step.NIGHTLY) throw IOException("the disk said no") })))
        val dated = s.dated(NIGHT_2)
        assertTrue(line.contains(dated.path) && line.contains(s.nightly.path), "names both: $line")
        assertTrue(line.contains("the disk said no"), line)
        assertTrue(exists(dated) && linkCount(dated) == 1, "tonight's snapshot exists under its dated name only")
        assertEquals(nightlyInode, inode(s.nightly), "the nightly name is last night's")
        assertNoTemporary(s)
        assertEquals(rows(copyAside(s.db)), rows(copyAside(dated)))
    }

    /** A dated name that exists already (two runs in one second, or a clock that went back to it). */
    @Test
    fun aDatedNameThatExistsAlready_isNotWrittenOver_andNothingEarlierChanges() {
        val s = heldServer()
        s.at(NIGHT_2)
        assertNull(backup(s))
        val before = tree(s.backup)
        val line = assertStoppedAt(Step.DATED, backup(s))
        assertTrue(line.contains(s.dated(NIGHT_2).path), line)
        assertEquals(before, tree(s.backup), "the dated file, the nightly name and the lock are as they were; no temporary file")
        assertEquals(1, status(s))
    }

    /**
     * The write-ahead file and the `-shm` file of the temporary name, which SQLite may make beside it and a killed run can
     * leave, are removed by the next run, whose snapshot is then checked and in place.
     */
    @Test
    fun theWriteAheadAndShmFilesOfTheTemporaryName_leftByAKilledRun_areRemovedByTheNextRun() {
        val s = heldServer()
        assertNull(backup(s))
        File(s.temporary.path + "-wal").writeText("a write-ahead file left by a run that was killed")
        File(s.temporary.path + "-shm").writeText("a shared-memory file left by a run that was killed")
        s.at(NIGHT_2)
        assertNull(backup(s))
        assertNoTemporary(s)
        assertEquals(inode(s.dated(NIGHT_2)), inode(s.nightly))
        assertEquals(rows(copyAside(s.db)), rows(copyAside(s.nightly)))
    }

    /** What a killed run left under the temporary names, ordinary files, is removed by the next run. */
    @Test
    fun aLeftoverOfAKilledRun_anOrdinaryFile_isRemovedByTheNextRun() {
        val s = heldServer()
        assertNull(backup(s))
        s.temporary.writeText("half a snapshot of a run that was killed")
        File(s.temporary.path + "-journal").writeText("its journal")
        s.at(NIGHT_2)
        assertNull(backup(s))
        assertNoTemporary(s)
        assertEquals(inode(s.dated(NIGHT_2)), inode(s.nightly))
    }

    // ---------------------------------------------------------------------------------------------------------------
    // No link is followed, nothing but the nightly name is written over
    // ---------------------------------------------------------------------------------------------------------------

    /**
     * A link in the place of the nightly name, of the lock and of the temporary name, dangling
     * and leading to a folder elsewhere. Each is refused with a line and status 1; nothing is made where it leads.
     */
    @Test
    fun aLinkInThePlaceOfTheNightlyNameTheLockOrTheTemporaryName_isRefused_andNothingIsMadeWhereItLeads() {
        for (name in listOf(ServerBackup.NIGHTLY, ServerBackup.LOCK, ServerBackup.TEMPORARY)) {
            for (kind in listOf("dangling", "to a folder elsewhere")) {
                val s = heldServer()
                val elsewhere = newFolder("elsewhere")
                val target = if (kind == "dangling") File(elsewhere, "not-there") else File(elsewhere, "folder").also { it.mkdir() }
                Files.createDirectory(s.backup.toPath())
                val link = File(s.backup, name)
                Files.createSymbolicLink(link.toPath(), target.toPath())
                val before = tree(elsewhere)
                val backupBefore = tree(s.backup)
                val line = assertStoppedAt(if (name == ServerBackup.LOCK) Step.LOCK else Step.NAMES, backup(s))
                assertTrue(line.contains(link.path), "$name $kind: names it: $line")
                assertEquals(before, tree(elsewhere), "$name $kind: nothing made or changed where it leads")
                // The lock file the run takes is the only new name, where the link is not in the lock's place.
                val lockMade = if (name == ServerBackup.LOCK) emptySet() else setOf(ServerBackup.LOCK)
                assertEquals(backupBefore, tree(s.backup) - lockMade, "$name $kind: the link stays, no snapshot is written")
                assertEquals(1, status(s), "$name $kind")
            }
        }
    }

    /** A folder in the place of the nightly name. */
    @Test
    fun aFolderInThePlaceOfTheNightlyName_isRefused_andStaysAsItWas() {
        val s = heldServer()
        Files.createDirectory(s.backup.toPath())
        Files.createDirectory(s.nightly.toPath())
        File(s.nightly, "kept.txt").writeText("mine")
        val before = tree(s.backup)
        val line = assertStoppedAt(Step.NAMES, backup(s))
        assertTrue(line.contains(s.nightly.path), line)
        assertEquals(before, tree(s.backup) - ServerBackup.LOCK)
        assertEquals(1, status(s))
    }

    /**
     * The database's own name a link to a file in a folder elsewhere: the backup folder is made in the data folder, beside
     * the link (where the restore lines name it), and nothing is made in the folder the link leads to.
     */
    @Test
    fun aLinkInTheDatabasesName_theBackupFolderIsMadeBesideTheLink() {
        val s = server()
        val elsewhere = newFolder("database-elsewhere")
        val real = File(elsewhere, s.db.name)
        Files.move(s.db.toPath(), real.toPath())
        Files.createSymbolicLink(s.db.toPath(), real.toPath())
        assertNull(backup(s))
        assertEquals(inode(s.dated(NIGHT_1)), inode(s.nightly))
        assertEquals(rows(copyAside(real)), rows(copyAside(s.nightly)))
        val besideReal = elsewhere.list()!!.toSet()
        assertTrue(
            s.db.name in besideReal && (besideReal - setOf(s.db.name, "${s.db.name}-wal", "${s.db.name}-shm")).isEmpty(),
            "the folder the link leads to holds the database and nothing else but the database's own -wal and -shm " +
                "(no backup folder, no snapshot, no lock file): $besideReal",
        )

        // A rollback journal beside the file the link leads to: the header read is that of the file the link leads to. Two
        // states: the server stopped cleanly after a stray journal was put beside its database while it ran (a write-ahead
        // header; the line says first where the file named lies), and a put-back snapshot with its own journal (the header
        // line, which names the link and the file it leads to).
        val at = "backup stopped at the database: "
        val linked = "${s.db.path} is a link to ${real.canonicalPath}: the file named here lies beside that file. "
        letGo(s)
        Db(s.db.path).use { running ->
            running.tx { c -> c.exec("INSERT INTO meta(key,value) VALUES(?,?)", "saved before the journal", "1") }
            Files.copy(File(stoppedWriter(s.nightly).path + "-journal").toPath(), File(real.path + "-journal").toPath())
        }
        assertEquals("header 2/2", header(real))
        assertEquals(listOf("-journal"), beside(real))
        s.at(NIGHT_2)
        val data = tree(s.data) + tree(elsewhere).mapKeys { "elsewhere/${it.key}" }
        val stopped = backup(s)
        assertEquals(data, tree(s.data) + tree(elsewhere).mapKeys { "elsewhere/${it.key}" }, "no byte changes on either side of the link")

        val putBack = stoppedWriter(s.nightly)
        Files.copy(putBack.toPath(), real.toPath(), StandardCopyOption.REPLACE_EXISTING)
        Files.copy(File(putBack.path + "-journal").toPath(), File(real.path + "-journal").toPath(), StandardCopyOption.REPLACE_EXISTING)
        assertEquals("header 1/1", header(real))
        val restoredTo = tree(s.data) + tree(elsewhere).mapKeys { "elsewhere/${it.key}" }
        val restoredLine = backup(s)
        assertEquals(restoredTo, tree(s.data) + tree(elsewhere).mapKeys { "elsewhere/${it.key}" }, "no byte changes on either side of the link")

        assertEquals(at + linked + writeAheadLine(s.db.name).removePrefix(at), stopped)
        assertEquals(notWriteAheadHeader("${s.db.path} (a link to ${real.canonicalPath})"), restoredLine)
    }

    /** The backup folder must be a real folder inside the data folder: not a link (to a folder elsewhere, or dangling), not a file. */
    @Test
    fun theBackupFolder_mustBeARealFolder() {
        for (kind in listOf("a link to a folder elsewhere", "a dangling link", "a file")) {
            val s = heldServer()
            val elsewhere = newFolder("elsewhere")
            when (kind) {
                "a link to a folder elsewhere" -> Files.createSymbolicLink(s.backup.toPath(), elsewhere.toPath())
                "a dangling link" -> Files.createSymbolicLink(s.backup.toPath(), File(elsewhere, "not-there").toPath())
                else -> s.backup.writeText("not a folder")
            }
            val data = tree(s.data)
            val line = assertStoppedAt(Step.FOLDER, backup(s))
            assertTrue(line.contains(s.backup.path), "$kind: $line")
            assertEquals(emptyMap(), tree(elsewhere).filterKeys { it.isNotEmpty() }, "$kind: nothing is made elsewhere")
            assertEquals(data, tree(s.data), kind)
        }
    }

    // ---------------------------------------------------------------------------------------------------------------
    // Keeping
    // ---------------------------------------------------------------------------------------------------------------

    private fun plantDated(s: Server, days: IntRange): List<File> {
        if (!exists(s.backup)) Files.createDirectory(s.backup.toPath())
        return days.map { k -> s.dated(NIGHT_1 - k * Clock.DAY_MS).also { it.writeText("an old snapshot, $k days old") } }
    }

    private fun datedLeft(s: Server): Set<String> = s.backup.list()!!.filter { ServerBackup.DATED.matches(it) }.toSet()

    /**
     * The newest 14 stay when `--keep` is left out; only ordinary files whose names match the dated pattern exactly
     * are removed; every other name stays as it was.
     */
    @Test
    fun theNewest14Stay_andOnlyOrdinaryFilesOfTheExactDatedPatternAreRemoved() {
        val s = heldServer()
        val old = plantDated(s, 1..16)
        val others = listOf(
            "andvari-nightly-2026-01-01-000000.db.bak", "andvari-nightly-2026-1-01-000000.db", "andvari-nightly-2026-01-01-0000000.db",
            "xandvari-nightly-2026-01-01-000000.db", "andvari-before-1.0.1.db", "notes.txt",
        ).map { File(s.backup, it).also { f -> f.writeText("the operator's own ${f.name}") } }
        Files.createSymbolicLink(File(s.backup, "andvari-nightly-2026-01-01-000000.db.link").toPath(), old.last().toPath())
        fun notOurs(t: Map<String, String>) = t.filterKeys { k -> k != "" && !ServerBackup.DATED.matches(k) && k != ServerBackup.LOCK && k != ServerBackup.NIGHTLY }
        val othersBefore = notOurs(tree(s.backup))
        assertEquals(7, othersBefore.size)
        assertNull(backup(s))
        assertEquals((listOf(s.dated(NIGHT_1)) + old.take(13)).map { it.name }.toSet(), datedLeft(s))
        assertEquals(othersBefore, notOurs(tree(s.backup)), "every other name is as it was")
        assertTrue(others.all { it.isFile })
    }

    /** `--keep 1` leaves tonight's alone; `--keep 999` removes none. */
    @Test
    fun keep1LeavesTonightsAlone_andKeep999RemovesNone() {
        val s = heldServer()
        plantDated(s, 1..3)
        assertNull(backup(s, "--keep", "1"))
        assertEquals(setOf(s.dated(NIGHT_1).name), datedLeft(s))

        val t = heldServer()
        val old = plantDated(t, 1..20)
        assertNull(backup(t, "--keep", "999"))
        assertEquals((old + t.dated(NIGHT_1)).map { it.name }.toSet(), datedLeft(t))
    }

    /**
     * Old snapshots are removed only once tonight's is in place: a run that fails before (here at the nightly name;
     * stand-in: the failure is thrown from the hook at that step) removes none of them, however many are past `--keep`.
     */
    @Test
    fun aRunThatFailsBeforeTonightsSnapshotIsInPlace_removesNoOldSnapshot() {
        val s = heldServer()
        val old = plantDated(s, 1..3)
        val line = assertStoppedAt(Step.NIGHTLY, backup(s, "--keep", "1", seams = Seams(serverHolds = true,atStep = { if (it == Step.NIGHTLY) throw IOException("the disk said no") })))
        assertTrue(old.all { it.isFile }, "every old snapshot stays: $line")
    }

    /** A clock that went back between two runs. Tonight's snapshot is one of those kept, whatever its date. */
    @Test
    fun aClockThatWentBack_keepsTonightsSnapshot_andTheNewestOthers() {
        val s = heldServer()
        s.at(NIGHT_3)
        assertNull(backup(s))
        s.at(NIGHT_4)
        assertNull(backup(s))
        s.at(NIGHT_1)
        assertNull(backup(s, "--keep", "2"))
        assertEquals(setOf(s.dated(NIGHT_1).name, s.dated(NIGHT_4).name), datedLeft(s))
        assertEquals(inode(s.dated(NIGHT_1)), inode(s.nightly), "the nightly name is tonight's")
    }

    /** A name of the dated pattern that is not an ordinary file is never removed; the line says tonight's snapshot is in place. */
    @Test
    fun aDatedNameThatIsNotAnOrdinaryFile_isNotRemoved_andTheLineSaysTonightsSnapshotIsInPlace() {
        for (kind in listOf("a folder", "a link")) {
            val s = heldServer()
            Files.createDirectory(s.backup.toPath())
            val odd = s.dated(NIGHT_1 - 5 * Clock.DAY_MS)
            val elsewhere = newFolder("elsewhere").also { File(it, "kept.txt").writeText("mine") }
            if (kind == "a folder") Files.createDirectory(odd.toPath()).also { File(odd, "kept.txt").writeText("mine") } else Files.createSymbolicLink(odd.toPath(), File(elsewhere, "kept.txt").toPath())
            val oddBefore = tree(odd)
            val line = assertStoppedAt(Step.KEEPING, backup(s, "--keep", "1"))
            assertTrue(line.contains(odd.path) && line.contains("tonight's snapshot is in place"), "$kind: $line")
            assertEquals(oddBefore, tree(odd), kind)
            assertEquals("mine", File(elsewhere, "kept.txt").readText())
            assertEquals(inode(s.dated(NIGHT_1)), inode(s.nightly), "$kind: tonight's snapshot is in place")
        }
    }

    /** A `--keep` given twice, in either spelling, is refused at the arguments, before anything is done. */
    @Test
    fun keepGivenTwice_isRefusedAtItsArguments_beforeAnythingIsDone() {
        val s = heldServer()
        assertNull(backup(s))
        plantDated(s, 1..10)
        s.at(NIGHT_2)
        val data = tree(s.data)
        for (twice in listOf(listOf("--keep", "3", "--keep", "5"), listOf("--keep=5", "--keep=3"))) {
            val line = assertStoppedAt(Step.ARGUMENTS, backup(s, *twice.toTypedArray()))
            assertTrue(line.contains("--keep is given more than once"), "$twice: $line")
            assertEquals(data, tree(s.data), "$twice: nothing was done")
            assertEquals(1, status(s, *twice.toTypedArray()), "$twice: status 1")
            assertEquals(data, tree(s.data), "$twice: nothing was done by the command line's run either")
        }
    }

    /** Anything but a whole number from 1 to 999 after `--keep` is refused before anything is done. */
    @Test
    fun keepOutsideOneTo999_isRefusedBeforeAnythingIsDone() {
        val s = heldServer()
        val data = tree(s.data)
        for (value in listOf("0", "1000", "a word", "abc", "12345678901234567890", "-1", "007", "")) {
            val line = assertStoppedAt(Step.ARGUMENTS, backup(s, "--keep=$value"))
            assertTrue(line.contains("--keep"), "$value: $line")
            assertEquals(data, tree(s.data), "'$value': nothing was done")
            assertEquals(1, status(s, "--keep", value), "'$value': status 1")
        }
        assertStoppedAt(Step.ARGUMENTS, backup(s, "--keep"))
        assertEquals(data, tree(s.data))
    }

    // ---------------------------------------------------------------------------------------------------------------
    // Room
    // ---------------------------------------------------------------------------------------------------------------

    /**
     * Less free room than the bound: refused with both numbers when the file system that holds
     * the backup folder has less than twice the database and its write-ahead file. Stand-in: the measured free room only.
     */
    @Test
    fun lessThanTwiceTheDatabaseAndItsWriteAheadFile_isRefusedWithBothNumbers() {
        val s = heldServer()
        heldOpen(s, "a save in the write-ahead file").use {
            val wal = File(s.db.path + "-wal").length()
            val need = 2 * (s.db.length() + wal)
            var measured: java.nio.file.Path? = null
            val line = assertStoppedAt(Step.ROOM, backup(s, seams = Seams(serverHolds = true,freeRoom = { p -> measured = p; need - 1 })))
            assertTrue(line.contains("${need - 1}") && line.contains("$need"), "both numbers ($need): $line")
            assertEquals(s.backup.toPath().toAbsolutePath().normalize(), measured?.toAbsolutePath()?.normalize(), "measured on the backup folder")
            assertFalse(s.backup.list()!!.any { it in snapshotNames || ServerBackup.DATED.matches(it) }, "nothing written")
            assertNull(backup(s, seams = Seams(serverHolds = true,freeRoom = { need })), "exactly twice is enough")
        }
    }

    // ---------------------------------------------------------------------------------------------------------------
    // One line for every failure, and no word form
    // ---------------------------------------------------------------------------------------------------------------

    /**
     * An error nobody foresaw is one line naming its step, and the run's temporary file is removed. Stand-in: the
     * error is thrown from the step hook, its message on two lines; at the removal of old snapshots the line also says
     * tonight's snapshot is in place.
     */
    @Test
    fun anErrorNobodyForesaw_isOneLineThatNamesTheStep() {
        val s = heldServer()
        val line = assertStoppedAt(Step.CHECK, backup(s, seams = Seams(serverHolds = true,atStep = { if (it == Step.CHECK) throw IllegalStateException("nobody\nforesaw this") })))
        assertTrue(line.contains("nobody foresaw this"), line)
        assertNoTemporary(s)
        assertFalse(exists(s.nightly))

        val keeping = assertStoppedAt(Step.KEEPING, backup(s, seams = Seams(serverHolds = true,atStep = { if (it == Step.KEEPING) throw IllegalStateException("at the end") })))
        assertTrue(keeping.contains("tonight's snapshot is in place"), keeping)
        assertEquals(inode(s.dated(NIGHT_1)), inode(s.nightly))
    }

    /** There is no word form and no named snapshot: a word or any other option is refused before anything is done. */
    @Test
    fun thereIsNoWordForm_andNoNamedSnapshot() {
        val s = heldServer()
        val data = tree(s.data)
        for (extra in listOf(listOf("before-1.0.1"), listOf("--name", "before-1.0.1"), listOf("--keep", "3", "nightly"), listOf("--force"))) {
            assertStoppedAt(Step.ARGUMENTS, backup(s, *extra.toTypedArray()))
            assertEquals(data, tree(s.data), "$extra: nothing was done")
            assertEquals(1, status(s, *extra.toTypedArray()), "$extra: status 1")
        }
    }
}
