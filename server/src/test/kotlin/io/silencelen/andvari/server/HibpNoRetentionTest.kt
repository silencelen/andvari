package io.silencelen.andvari.server

import java.io.File
import java.sql.DriverManager
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse

/**
 * Security review 2026-10, root cause C: the relay used to keep every prefix it fetched in
 * `hibp_cache(prefix, body, fetchedAt)` for up to 45 days, in the same database as the Argon2id
 * verifier and the timestamped `register` / `password_change` audit rows. Pairing a cache row
 * with the audit row written seconds earlier handed a DB or backup holder 20 bits of the
 * account's master-password SHA-1. No client sends a master-password prefix any more, and the
 * relay that remains (item passwords, Health scan) stores nothing, so the table has no reason to
 * exist — and a server upgraded from a version that had it must lose the rows ON DISK, not just
 * unlink them from the schema.
 */
class HibpNoRetentionTest : P4TestSupport() {

    private fun tableExists(db: Db, name: String): Boolean =
        (db.read { c -> c.queryOne("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?", name) { it.getLong(1) } } ?: 0L) > 0L

    @Test
    fun aFreshDatabase_hasNowhereToKeepAPrefix() {
        Db(File(tmpDir, "fresh-${System.nanoTime()}.db").absolutePath).use { db ->
            assertFalse(tableExists(db, "hibp_cache"), "a fresh schema must not carry the prefix cache")
        }
    }

    @Test
    fun anUpgradedDatabase_purgesRetainedPrefixes_offTheDisk() {
        val path = File(tmpDir, "upgrade-${System.nanoTime()}.db").absolutePath
        // A distinctive body, so a byte scan of the file can only match this row's leftovers.
        val marker = "STALEPREFIXMARKER0123456789ABCDEF:1337"
        Db(path).close()
        // Put the file back into the shape a pre-fix server left it in: schema v10, and a
        // populated hibp_cache (CREATE IF NOT EXISTS — on the old schema the table is already there).
        DriverManager.getConnection("jdbc:sqlite:$path").use { c ->
            c.createStatement().use { st ->
                st.executeUpdate("CREATE TABLE IF NOT EXISTS hibp_cache(prefix TEXT PRIMARY KEY, body TEXT NOT NULL, fetchedAt INTEGER NOT NULL)")
                for (i in 0 until 64) {
                    st.executeUpdate("INSERT INTO hibp_cache(prefix,body,fetchedAt) VALUES('${"%05X".format(i)}','$marker',1)")
                }
                st.executeUpdate("UPDATE meta SET value='10' WHERE key='schemaVersion'")
                st.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            }
        }

        Db(path).use { db ->
            assertFalse(tableExists(db, "hibp_cache"), "the upgrade must drop the prefix cache")
        }
        // Freed pages keep their old bytes unless they are overwritten: dropping the table alone
        // would leave every prefix readable in the file (and in the next backup of it).
        for (f in listOf(File(path), File("$path-wal"))) {
            if (!f.exists()) continue
            val text = String(f.readBytes(), Charsets.ISO_8859_1)
            assertFalse(text.contains(marker), "${f.name} still holds a purged hibp_cache row")
        }
        DriverManager.getConnection("jdbc:sqlite:$path").use { c ->
            c.createStatement().use { st ->
                st.executeQuery("SELECT value FROM meta WHERE key='schemaVersion'").use { rs ->
                    rs.next()
                    assertEquals("11", rs.getString(1))
                }
            }
        }
    }
}
