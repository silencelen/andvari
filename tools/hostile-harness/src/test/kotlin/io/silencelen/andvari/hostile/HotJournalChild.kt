package io.silencelen.andvari.hostile

import java.sql.DriverManager

/**
 * A process of its own, for [RestoredStartTest]: a program writing the database (args[0]) that is stopped part-way, as a
 * run of `andvari admin restored` killed inside its transaction is. It opens the file in SQLite's rollback mode, begins a
 * transaction, ends every session and writes enough rows that SQLite must spill changed pages into the database file
 * itself (a cache of a few pages), prints `ready`, and waits to be killed. What it leaves beside the file is a hot
 * rollback journal: the only thing that puts the file back as it was.
 */
object HotJournalChild {
    @JvmStatic fun main(args: Array<String>) {
        DriverManager.getConnection("jdbc:sqlite:${args[0]}").use { c ->
            c.createStatement().use { st ->
                st.execute("PRAGMA cache_size=10")
                st.execute("BEGIN EXCLUSIVE")
                st.executeUpdate("UPDATE sessions SET revokedAt=1 WHERE revokedAt IS NULL")
                st.executeUpdate(
                    "INSERT INTO meta(key,value) WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i<20000) " +
                        "SELECT 'unfinished '||i, hex(randomblob(200)) FROM n",
                )
            }
            println("ready")
            System.out.flush()
            Thread.sleep(600_000)
        }
    }
}
