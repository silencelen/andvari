package io.silencelen.andvari.server

import java.io.File
import java.nio.file.Files
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * H84 (audit 2026-09-13): the server answers a push `applied` only after the item row, its
 * `changes` rev and the `mutations` idempotency row commit together — and the client then drops
 * that mutation from its outbox. Under WAL + `synchronous=NORMAL` such a commit is acknowledged
 * before any fsync and can roll back on power loss, taking the dedup row that would have let a
 * replay happen with it, so an acknowledged save is silently lost. The owner's call is
 * `synchronous=FULL`: one fsync per commit, bought with throughput nobody at household scale is
 * spending.
 *
 * This pins the PRAGMA as it is actually applied to the live connection (not as a string in the
 * source): a revert to NORMAL — or to any other mode, including a well-meant OFF for an importer
 * run — turns this red.
 */
class DbDurabilityTest {
    private val tmpDir: File = Files.createTempDirectory("andvari-db-durability").toFile()

    @AfterTest fun cleanup() { tmpDir.deleteRecursively() }

    private fun pragma(db: Db, name: String): String = db.read { c ->
        c.createStatement().use { st ->
            st.executeQuery("PRAGMA $name").use { rs -> if (rs.next()) rs.getString(1) else "" }
        }
    }

    @Test
    fun connectionIsWalWithFullSynchronousDurability() {
        Db(File(tmpDir, "durability.db").absolutePath).use { db ->
            // SQLite's PRAGMA synchronous reports the enum, not the word: 0=OFF, 1=NORMAL,
            // 2=FULL, 3=EXTRA. Anything but 2 means an acknowledged commit can vanish on a
            // power cut inside the checkpoint window (H84).
            assertEquals("2", pragma(db, "synchronous"), "PRAGMA synchronous must be FULL (2) — see Db.kt's H84 note")
            // FULL is only the whole story while the journal is WAL: the two PRAGMAs are set
            // together and reasoned about together.
            assertEquals("wal", pragma(db, "journal_mode").lowercase())
        }
    }

    /** The durable connection is still a working one — the PRAGMA is set before migrate() runs. */
    @Test
    fun writesStillCommitAndReadBack() {
        Db(File(tmpDir, "durability-rw.db").absolutePath).use { db ->
            db.tx { c -> c.exec("INSERT OR REPLACE INTO meta(key,value) VALUES('h84','durable')") }
            val v = db.read { c -> c.queryOne("SELECT value FROM meta WHERE key='h84'") { rs -> rs.getString(1) } }
            assertEquals("durable", v)
        }
    }
}
