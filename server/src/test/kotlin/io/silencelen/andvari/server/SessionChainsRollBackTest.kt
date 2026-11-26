package io.silencelen.andvari.server

import io.ktor.server.testing.testApplication
import java.io.File
import java.sql.Connection
import java.sql.DriverManager
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * The refresh chain of a session is kept in a table of its own, `session_chains`, so that a server of the version before
 * starts on a database this one has run on (decided on 2026-11-17: a roll-back of the server is kept possible at every
 * deploy). A development build of 2026-11-17 kept it in a column `sessions.chainId`, and the version before refused to
 * start on a database that had it ("sessions has chainId, which the baseline no longer has").
 *
 * **How a roll-back is shown without running the older build.** Its start-up step compares the database with its own
 * schema table by table and index by index, and refuses or changes the database exactly when [BaselineCatchUp.differences]
 * against that schema is not empty (tables it does not name are not looked at). So the older build accepts a database
 * as it is when that list is empty. The schema of the version before (the server as it stood on 17 November 2026) is rebuilt here from the frozen
 * `baseline-history/` file and the changes made to the baseline since that file, each named; it was compared line by line
 * with that version's `server/src/main/kotlin/io/silencelen/andvari/server/Db.kt` when this test was written, and the
 * first test checks it against the current baseline: the two differ by the new table alone.
 */
class SessionChainsRollBackTest {
    private val oldest: String = javaClass.getResource("/baseline-history/onboarding-trust-1-before-decoy-requests.sql")!!.readText()

    /** The baseline as the version before created it: the frozen file with the four changes made to it since, each checked. */
    private val atD914: String = oldest
        // 15 November 2026: a decoy request's userId is NULL.
        .swap("userId TEXT NOT NULL REFERENCES users(userId),\n     emailHash", "userId TEXT REFERENCES users(userId),\n     emailHash")
        // 16 November 2026, and the cancellation: the commit hash and when the owner cancelled (the commit count was later retired).
        .swap("     holdEndsAt INTEGER,\n     sealed TEXT\n   );", "     holdEndsAt INTEGER,\n     sealed TEXT,\n     commitHash TEXT,\n     cancelledAt INTEGER\n   );")
        // The mailbox values of a recovery request.
        .swap(
            "CREATE INDEX idx_recovery_requests_user ON recovery_requests(userId);\n",
            "CREATE INDEX idx_recovery_requests_user ON recovery_requests(userId);\nCREATE TABLE recovery_mailbox_values(\n     valueHash TEXT PRIMARY KEY,\n" +
                "     emailHash TEXT NOT NULL,\n     expiresAt INTEGER NOT NULL\n   );\nCREATE INDEX idx_recovery_mailbox_values_email ON recovery_mailbox_values(emailHash);\n",
        )
        // 16 November 2026: the covering index of an item's live size.
        .swap(
            "CREATE INDEX idx_items_deleted_updated ON items(updatedAt) WHERE deleted=1;\n",
            "CREATE INDEX idx_items_deleted_updated ON items(updatedAt) WHERE deleted=1;\nCREATE INDEX idx_items_vault_live_size ON items(vaultId, deleted, blobSize);\n",
        )

    private fun String.swap(from: String, to: String): String = replace(from, to).also { check(it != this) { "not in the frozen file: $from" } }

    private fun statements(sql: String): List<String> =
        sql.lines().filter { !it.trimStart().startsWith("--") }.joinToString("\n").split(";\n").map { it.trim().removeSuffix(";") }.filter { it.isNotEmpty() }

    private val d914Schema: List<String> by lazy { statements(atD914) }

    private fun raw(path: String): Connection = DriverManager.getConnection("jdbc:sqlite:$path").also {
        it.createStatement().use { st -> st.execute("PRAGMA foreign_keys=ON") }
    }

    /** What the version before would say of the database at [path]: empty when its start-up step takes it as it is. */
    private fun asTheVersionBeforeSeesIt(path: String): List<String> = raw(path).use { BaselineCatchUp.differences(it, d914Schema) }

    private fun chains(path: String): Map<String, String> =
        raw(path).use { c -> c.queryAll("SELECT sessionId,chainId FROM session_chains") { it.getString(1) to it.getString(2) }.toMap() }

    class Chain(val userId: String, val deviceId: String, val first: IssuedSession, val second: IssuedSession, val third: IssuedSession)

    /**
     * A current server in [dir] holds an account with one device and a chain of three sessions: a sign-in's, and two
     * refreshes' (each rotated-away session consumed), as the refresh route makes them.
     */
    private fun chainIn(dir: File): Chain {
        var out: Chain? = null
        testApplication {
            val s = TestKit.services(TestKit.config(dir = dir))
            application { andvariModule(s) }
            Flow.finishSetup(client, s)
            val me = Flow.member(client, s, "me@example.com")
            out = s.db.tx { c ->
                fun next(prev: IssuedSession?, chain: String?): IssuedSession {
                    prev?.let { c.exec("UPDATE sessions SET refreshConsumedAt=? WHERE sessionId=?", s.clock.now(), it.sessionId) }
                    return s.sessions.issue(c, me.userId, me.deviceId, "linux", passwordLogin = prev == null, chainId = chain)
                }
                val a = next(null, null)
                val b = next(a, a.sessionId)
                Chain(me.userId, me.deviceId, a, b, next(b, a.sessionId))
            }
            s.db.close()
        }
        return out!!
    }

    /** The chain's first session's refresh token, sent by a sign-in that names it, ends the chain's live session only. */
    private fun namingTheFirstEndsTheThird(dir: File, ch: Chain) {
        val s = TestKit.services(TestKit.config(dir = dir))
        try {
            val end = assertNotNull(s.db.tx { c -> s.sessions.endNamed(c, ch.userId, ch.deviceId, ServerCrypto.hashToken(ch.first.refreshToken)) })
            assertEquals(listOf(ch.third.sessionId), end.liveSessionIds)
            assertTrue(end.replaced)
        } finally {
            s.db.close()
        }
    }

    /** The derived schema of the version before is the current baseline without the new table: nothing else differs. */
    @Test
    fun aDatabaseMadeByTheVersionBefore_gainsTheTable_andTheVersionBeforeStillTakesIt() {
        val dir = TestKit.tempDir()
        val path = File(dir, "andvari.db").path
        raw(path).use { c -> c.createStatement().use { st -> for (ddl in d914Schema) st.executeUpdate(ddl) } }
        raw(path).use { c ->
            assertEquals(listOf("table session_chains is missing", "index idx_session_chains_chain is missing"), BaselineCatchUp.differences(c))
        }
        assertEquals(emptyList(), asTheVersionBeforeSeesIt(path))
        Db(path, durable = false).use { assertEquals(listOf("created table session_chains"), it.addedAtStart) }
        raw(path).use { c -> assertEquals(emptyList(), BaselineCatchUp.differences(c)) }
        // The roll-back: the version before takes the database this version has run on, as it is.
        assertEquals(emptyList(), asTheVersionBeforeSeesIt(path))
    }

    /**
     * A database the column's build ran on: the chain the column held is carried into the new table, the column goes,
     * and the chain still works. Before the start, the version before refused it (the column); after, it takes it.
     */
    @Test
    fun aDatabaseTheColumnsBuildRanOn_keepsItsChains_losesTheColumn_andTheVersionBeforeTakesIt() {
        val dir = TestKit.tempDir()
        val path = File(dir, "andvari.db").path
        val ch = chainIn(dir)
        // As the column's build left it: no table, the column, every session naming its chain (its own id at a start).
        raw(path).use { c ->
            c.createStatement().use { st ->
                st.executeUpdate("DROP TABLE session_chains")
                st.executeUpdate("ALTER TABLE sessions ADD COLUMN chainId TEXT")
                st.executeUpdate("UPDATE sessions SET chainId=sessionId")
            }
            c.exec("UPDATE sessions SET chainId=? WHERE sessionId IN (?,?)", ch.first.sessionId, ch.second.sessionId, ch.third.sessionId)
            assertEquals(
                listOf("sessions.chainId is not in the baseline", "table session_chains is missing", "index idx_session_chains_chain is missing"),
                BaselineCatchUp.differences(c),
            )
        }
        assertEquals(listOf("sessions.chainId is not in the baseline"), asTheVersionBeforeSeesIt(path), "the version before refuses the column")
        val sessionsBefore = raw(path).use { c -> c.count("SELECT COUNT(*) FROM sessions") }

        Db(path, durable = false).use { db ->
            assertEquals(
                listOf(
                    "created table session_chains",
                    "carried 2 refresh chain links from sessions.chainId into session_chains",
                    "rebuilt sessions: dropping the retired chainId",
                ),
                db.addedAtStart,
            )
        }
        assertEquals(mapOf(ch.second.sessionId to ch.first.sessionId, ch.third.sessionId to ch.first.sessionId), chains(path))
        raw(path).use { c ->
            assertEquals(emptyList(), BaselineCatchUp.differences(c))
            assertEquals(sessionsBefore, c.count("SELECT COUNT(*) FROM sessions"), "every session is kept")
        }
        assertEquals(emptyList(), asTheVersionBeforeSeesIt(path), "the roll-back: the version before takes it as it is")
        Db(path, durable = false).use { assertEquals(emptyList(), it.addedAtStart, "a second start does nothing") }
        namingTheFirstEndsTheThird(dir, ch)
    }

    /**
     * What the version before does on a database this one ran on, and what this one finds when it comes back. The version
     * before writes sessions in its own column list and deletes them (an account deletion), which the new table, with no
     * reference to `sessions`, never blocks; back on this version, the start changes nothing and the janitor removes the
     * chain rows whose sessions are gone.
     */
    @Test
    fun theVersionBefore_writesAndDeletesSessions_andThisVersionTidiesUpAfterIt() {
        val dir = TestKit.tempDir()
        val path = File(dir, "andvari.db").path
        val ch = chainIn(dir)
        assertEquals(mapOf(ch.second.sessionId to ch.first.sessionId, ch.third.sessionId to ch.first.sessionId), chains(path))
        assertEquals(emptyList(), asTheVersionBeforeSeesIt(path))
        raw(path).use { c ->
            // The version before's own insert (its Sessions.issue, column for column) and its account deletion's delete.
            c.exec(
                """INSERT INTO sessions(sessionId,deviceId,userId,accessHash,accessExpiresAt,refreshHash,refreshExpiresAt,clientPlatform,passwordAt,createdAt)
                   VALUES(?,?,?,?,?,?,?,?,?,?)""",
                uuid(), ch.deviceId, ch.userId, "a".repeat(64), Long.MAX_VALUE / 4, "b".repeat(64), Long.MAX_VALUE / 4, "linux", null, 1L,
            )
            c.exec("DELETE FROM sessions WHERE userId=?", ch.userId)
            assertEquals(0L, c.count("SELECT COUNT(*) FROM sessions WHERE userId=?", ch.userId))
        }
        assertEquals(2, chains(path).size, "the version before does not know the table, so its rows stay")
        val s = TestKit.services(TestKit.config(dir = dir))
        try {
            assertEquals(emptyList(), s.db.addedAtStart)
            Janitor(s).sweep()
            assertEquals(emptyMap(), chains(path), "the janitor removes the rows whose sessions are gone")
        } finally {
            s.db.close()
        }
    }
}
