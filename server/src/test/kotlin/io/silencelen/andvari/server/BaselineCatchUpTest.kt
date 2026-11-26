package io.silencelen.andvari.server

import io.ktor.client.HttpClient
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpMethod
import io.ktor.server.testing.testApplication
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.model.wire.EscrowUpload
import io.silencelen.andvari.core.model.wire.RecoveryRequestCreated
import io.silencelen.andvari.core.model.wire.RecoveryVerifyResponse
import io.silencelen.andvari.core.model.wire.WireJson
import java.io.File
import java.sql.Connection
import java.sql.DriverManager
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * A database made before the baseline gained what it has now still starts and works (spec 02 §5.1): the start-up
 * step ([BaselineCatchUp]) brings it up to the baseline inside the start-up's transaction, and adds nothing the
 * second time. The older databases are built from the baseline's table definitions as they were, frozen in
 * `baseline-history/` (taken with `git show`), and filled with the rows a current server wrote, so they hold an
 * account, its devices and sessions, and a pending recovery request, exactly as an older database would.
 */
class BaselineCatchUpTest {
    private fun b32() = Bytes.toB64(TestKit.crypto.randomBytes(32))

    /** The baseline before decoy requests (15 November 2026): recovery_requests.userId NOT NULL, and neither commit column. */
    private val beforeDecoys: String =
        javaClass.getResource("/baseline-history/onboarding-trust-1-before-decoy-requests.sql")!!.readText()

    /** The baseline before the commit columns (16 November 2026): as [beforeDecoys] with the one change decoy requests made (a decoy's userId is NULL). */
    private val beforeCommitColumns: String =
        beforeDecoys.replace("userId TEXT NOT NULL REFERENCES users(userId),\n     emailHash", "userId TEXT REFERENCES users(userId),\n     emailHash")
            .also { check(it != beforeDecoys) }

    /**
     * The baseline from the commit columns (16 November 2026) until the commit count was retired: as [beforeCommitColumns] with
     * both commit columns, `commitAttempts` among them. The covering index of an item's live size (added later on 16 November 2026) is left out, as on the older
     * ones (a database made between the two lacks it).
     */
    private val withCommitAttempts: String =
        beforeCommitColumns.replace(
            "     holdEndsAt INTEGER,\n     sealed TEXT\n   );",
            "     holdEndsAt INTEGER,\n     sealed TEXT,\n     commitHash TEXT,\n     commitAttempts INTEGER NOT NULL DEFAULT 0\n   );",
        ).also { check(it != beforeCommitColumns) }

    private fun statements(sql: String): List<String> =
        sql.lines().filter { !it.trimStart().startsWith("--") }.joinToString("\n").split(";\n").map { it.trim() }.filter { it.isNotEmpty() }

    private fun raw(path: String): Connection = DriverManager.getConnection("jdbc:sqlite:$path")

    /** What the server reads as each table's columns: (name, type, notnull, default, pk) by table. */
    private fun columns(c: Connection): Map<String, Set<List<String?>>> {
        val tables = c.queryAll("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'") { it.getString(1) }
        return tables.associateWith { t ->
            c.queryAll("PRAGMA table_info($t)") { rs -> listOf(rs.getString("name"), rs.getString("type"), rs.getString("notnull"), rs.getString("dflt_value"), rs.getString("pk")) }.toSet()
        }
    }

    /** Each index the database defines: name, its table, and its columns as SQLite reads them (with the partial-index flag). */
    private fun indexes(c: Connection): Set<List<String?>> =
        c.queryAll("SELECT name, tbl_name FROM sqlite_master WHERE type='index' AND sql IS NOT NULL") { it.getString(1) to it.getString(2) }
            .map { (name, table) ->
                val cols = c.queryAll("PRAGMA index_info($name)") { it.getString("name") }.joinToString(",")
                val partial = c.queryAll("PRAGMA index_list($table)") { it.getString("name") to it.getString("partial") }.toMap()[name]
                listOf(name, table, cols, partial)
            }.toSet()

    private fun fresh(): String {
        val path = File(TestKit.tempDir(), "fresh.db").path
        Db(path, durable = false).close()
        return path
    }

    /** Every table of the baseline, with exactly the baseline's columns, and every index it names, in the database at [path]. */
    private fun assertMatchesTheBaseline(path: String) {
        val base = fresh()
        val want = raw(base).use { columns(it) }
        val have = raw(path).use { columns(it) }
        for ((t, cols) in want) assertEquals(cols, have[t], "table $t")
        assertEquals(raw(base).use { indexes(it) }, raw(path).use { indexes(it) })
        raw(path).use { c -> assertEquals(emptyList(), BaselineCatchUp.differences(c)) }
    }

    /** A missing index is created at start, and one defined differently is made again as the baseline defines it. */
    @Test
    fun everyIndexTheBaselineNames_existsAfterStart() {
        val path = File(TestKit.tempDir(), "andvari.db").path
        Db(path, durable = false).close()
        raw(path).use { c ->
            c.createStatement().use { st ->
                st.execute("DROP INDEX idx_device_links_device")
                st.execute("DROP INDEX idx_audit_type_at")
                st.execute("CREATE INDEX idx_audit_type_at ON audit(type)")
            }
            assertEquals(
                listOf("index idx_device_links_device is missing", "index idx_audit_type_at is 'CREATE INDEX idx_audit_type_at ON audit(type)', the baseline has 'CREATE INDEX idx_audit_type_at ON audit(type, at)'"),
                BaselineCatchUp.differences(c),
            )
        }
        Db(path, durable = false).use { db -> assertEquals(listOf("created index idx_device_links_device", "rebuilt index idx_audit_type_at"), db.addedAtStart) }
        assertMatchesTheBaseline(path)
        Db(path, durable = false).use { db -> assertEquals(emptyList(), db.addedAtStart) }
    }

    class World(val op: Me, val me: Me, val poll: String, val requestId: String, val key: ByteArray)

    /** A current server writes an operator, an operator-posture member and one unverified request for the member into [dir]. */
    private fun populate(dir: File): World {
        var world: World? = null
        val key = TestKit.Identity().curvePub
        testApplication {
            val s = TestKit.services(TestKit.config(dir = dir, recoveryKey = key))
            application { andvariModule(s) }
            val op = Flow.finishSetup(client, s)
            val me = Me("me@example.com")
            Flow.register(client, s, me, Flow.enrolAuth(s), "operator", Flow.escrow(me, sha256Hex(key)))
            val poll = TestKit.crypto.randomBytes(32)
            val body = """{"email":"${me.email}","rPub":"${b32()}","pollHash":"${sha256Hex(poll)}","platform":"android"}"""
            val reqId = WireJson.json.decodeFromString(RecoveryRequestCreated.serializer(), client.call(HttpMethod.Post, "/api/v1/recovery/requests", body).bodyAsText()).requestId
            world = World(op, me, Bytes.toB64(poll), reqId, key)
            s.db.close()
        }
        return world!!
    }

    /** A database at [path] made from the older [schema], holding every row of the current database at [from]. */
    private fun olderDatabase(schema: String, from: String, path: String) {
        raw(path).use { c ->
            c.createStatement().use { st ->
                for (ddl in statements(schema)) st.executeUpdate(ddl)
                st.execute("ATTACH DATABASE '$from' AS src")
            }
            val old = columns(c).filterKeys { it != "meta" }
            val src = raw(from).use { columns(it) }
            c.createStatement().use { st ->
                for ((t, cols) in old) {
                    // A column the current baseline retired takes its default (the current server has no value for it).
                    val have = src[t].orEmpty().map { it[0] }.toSet()
                    val names = cols.map { it[0]!! }.filter { it in have }.joinToString(",")
                    st.executeUpdate("INSERT INTO main.$t($names) SELECT $names FROM src.$t")
                }
                st.executeUpdate("INSERT OR REPLACE INTO main.meta SELECT * FROM src.meta WHERE key<>'baseline'")
            }
        }
    }

    private fun session(s: Services, userId: String, deviceId: String): String =
        s.db.tx { c -> s.sessions.issue(c, userId, deviceId, "linux", passwordLogin = true).accessToken }

    private fun state(s: Services, reqId: String): String? =
        s.db.read { c -> c.queryOne("SELECT state FROM recovery_requests WHERE requestId=?", reqId) { it.getString(1) } }

    private val kdf = """"newKdfSalt":"${Bytes.toB64(ByteArray(16) { 5 })}","newKdfParams":{"v":1,"alg":"argon2id13","ops":1,"memBytes":8388608},"newWrappedUvk":"AAAA""""

    /** The older database starts, and every route that writes the new columns works on it; a second start adds nothing. */
    private fun startsAndWorks(schema: String, expectBefore: List<String>, expectAdded: List<String>) {
        val current = TestKit.tempDir()
        val w = populate(current)
        val dir = TestKit.tempDir()
        val path = File(dir, "andvari.db").path
        olderDatabase(schema, File(current, "andvari.db").path, path)
        raw(path).use { c -> assertEquals(expectBefore, BaselineCatchUp.differences(c)) }
        testApplication {
            val clock = MutableClock()
            val s = TestKit.services(TestKit.config(dir = dir, recoveryKey = w.key), clock)
            application { andvariModule(s) }
            // The older database's rows survived: the account's pending request is still there.
            assertEquals("unverified", state(s, w.requestId))
            runAll(client, s, clock, w)
            assertEquals(expectAdded, s.db.addedAtStart)
            assertMatchesTheBaseline(path)
            s.db.close()
        }
        // A second start adds nothing.
        Db(path, durable = false).use { db -> assertEquals(emptyList(), db.addedAtStart) }
        assertMatchesTheBaseline(path)
    }

    @Test
    fun aDatabaseMadeBeforeTheCommitColumns_startsAndWorks() = startsAndWorks(
        beforeCommitColumns,
        expectBefore = listOf(
            "table session_chains is missing",
            "recovery_requests.commitHash is missing", "recovery_requests.cancelledAt is missing", "table recovery_mailbox_values is missing",
            "index idx_session_chains_chain is missing",
            "index idx_items_vault_live_size is missing", "index idx_recovery_mailbox_values_email is missing",
        ),
        expectAdded = listOf(
            "created table session_chains",
            "added recovery_requests.commitHash", "added recovery_requests.cancelledAt", "created table recovery_mailbox_values",
            "created index idx_items_vault_live_size",
        ),
    )

    /**
     * A database made while the baseline still counted wrong commit values starts and works:
     * the step drops the retired `recovery_requests.commitAttempts` by rebuilding the table, its rows kept. Before,
     * the step refused it (a column the baseline no longer has), and the old code wrote the column at every wrong value.
     */
    @Test
    fun aDatabaseWithTheRetiredCommitCount_startsAndWorks_andLosesTheColumn() = startsAndWorks(
        withCommitAttempts,
        expectBefore = listOf(
            "table session_chains is missing",
            "recovery_requests.cancelledAt is missing", "recovery_requests.commitAttempts is not in the baseline", "table recovery_mailbox_values is missing",
            "index idx_session_chains_chain is missing",
            "index idx_items_vault_live_size is missing", "index idx_recovery_mailbox_values_email is missing",
        ),
        expectAdded = listOf(
            "created table session_chains",
            "rebuilt recovery_requests: dropping the retired commitAttempts; adding cancelledAt", "created table recovery_mailbox_values",
            "created index idx_items_vault_live_size",
        ),
    )

    /**
     * The start-up's step for answers of the old form (spec 02 §5.1). An older database that already holds a request as answered holds an
     * answer of the old form and no commit hash: at the start it goes back to verified and waiting for the operator,
     * the stored answer dropped, and the start's log line says how many; the operator answers it again and the person
     * commits. Before, it stayed `ready` with an answer no device takes and a value nothing can match. Then a
     * stranger's attempt on the same database: a stranger with no session opens a request for the member, and the
     * member's sync and request list still answer.
     */
    @Test
    fun anOlderDatabasesAnsweredRequest_goesBackToTheOperator_andAStrangersRequestBreaksNothing() {
        val current = TestKit.tempDir()
        val w = populate(current)
        val dir = TestKit.tempDir()
        val path = File(dir, "andvari.db").path
        olderDatabase(beforeCommitColumns, File(current, "andvari.db").path, path)
        // As an older server left it: verified, its hold over, and answered with an old-form answer.
        val start = MutableClock().ms
        raw(path).use { c ->
            c.exec(
                "UPDATE recovery_requests SET state='fulfilled', codeMac=NULL, verifiedAt=?, holdEndsAt=?, sealed=? WHERE requestId=?",
                start - Assisted.HOLD_MS - 1_000, start - 1_000, Bytes.toB64(ByteArray(300)), w.requestId,
            )
        }
        testApplication {
            val clock = MutableClock()
            val s = TestKit.services(TestKit.config(dir = dir, recoveryKey = w.key), clock)
            application { andvariModule(s) }
            assertEquals(
                listOf(
                    "created table session_chains",
                    "added recovery_requests.commitHash", "added recovery_requests.cancelledAt", "created table recovery_mailbox_values",
                    "created index idx_items_vault_live_size",
                    "returned 1 answered recovery request of the old form to waiting for the operator, the stored answer dropped",
                ),
                s.db.addedAtStart,
            )
            assertEquals("verified", state(s, w.requestId))
            assertEquals(null, s.db.read { c -> c.queryOne("SELECT sealed FROM recovery_requests WHERE requestId=?", w.requestId) { it.getString(1) } })
            val poll = client.call(HttpMethod.Post, "/api/v1/recovery/requests/${w.requestId}/poll", """{"pollSecret":"${w.poll}"}""").bodyAsText()
            assertTrue(""""state":"awaiting_operator"""" in poll, poll)
            val opToken = session(s, w.op.userId, w.op.deviceId)
            val listed = client.call(HttpMethod.Get, "/api/v1/admin/recovery-requests", token = opToken).bodyAsText()
            assertTrue(""""requestId":"${w.requestId}"""" in listed && """"state":"awaiting_operator"""" in listed, listed)
            // The operator answers it again, and the person commits with the new answer's value.
            val rPub = s.db.read { c -> c.queryOne("SELECT rPub FROM recovery_requests WHERE requestId=?", w.requestId) { it.getString(1) } }!!
            val commit = TestKit.crypto.randomBytes(32)
            val sealed = Bytes.toB64(TestKit.crypto.randomBytes(io.silencelen.andvari.core.trust.AnswerToken.sealedBytes(w.me.email)))
            val hash = io.silencelen.andvari.core.trust.AssistedRecovery.commitHash(TestKit.crypto, commit)
            val up = client.call(
                HttpMethod.Post, "/api/v1/admin/recovery-requests/${w.requestId}/fulfil",
                """{"sealed":"$sealed","requestKey":"$rPub","commitHash":"$hash","currentAuthKey":"${w.op.authKey}"}""", opToken,
            )
            assertEquals(200, up.status.value, up.bodyAsText())
            // A stranger's attempt, while that request is answered: a stranger with no session opens one for the member ...
            val stranger = """{"email":"${w.me.email}","rPub":"${b32()}","pollHash":"${sha256Hex(TestKit.crypto.randomBytes(32))}","platform":"android"}"""
            assertEquals(202, client.call(HttpMethod.Post, "/api/v1/recovery/requests", stranger).status.value)
            // ... and the member's sync and list of requests answer.
            val meToken = session(s, w.me.userId, w.me.deviceId)
            val sync = client.call(HttpMethod.Get, "/api/v1/sync?since=0", token = meToken)
            assertEquals(200, sync.status.value, sync.bodyAsText())
            val list = client.call(HttpMethod.Get, "/api/v1/account/recovery-requests", token = meToken)
            assertEquals(200, list.status.value, list.bodyAsText())
            assertTrue(""""requestId":"${w.requestId}"""" in list.bodyAsText() && """"state":"ready"""" in list.bodyAsText(), list.bodyAsText())
            val tail = """$kdf,"newMemberRecovery":{"recoveryWrappedUvk":"AAAA","recoveryAuthKey":"${b32()}"},"device":{"platform":"ios","name":"x","deviceSecret":"${b32()}"}"""
            val ac = client.call(
                HttpMethod.Post, "/api/v1/recovery/requests/${w.requestId}/commit",
                """{"pollSecret":"${w.poll}","commit":"${Bytes.toB64(commit)}","newAuthKey":"${b32()}",$tail}""",
            )
            assertEquals(200, ac.status.value, ac.bodyAsText())
            s.db.close()
        }
        // A second start finds nothing to return.
        Db(path, durable = false).use { db -> assertEquals(emptyList(), db.addedAtStart) }
    }

    /** A column the baseline does not have and did not retire still refuses the start, changing nothing. */
    @Test
    fun aColumnNeitherInTheBaselineNorRetired_refusesTheStart() {
        val path = File(TestKit.tempDir(), "andvari.db").path
        val schema = withCommitAttempts.replace("     commitAttempts INTEGER NOT NULL DEFAULT 0\n", "     commitAttempts INTEGER NOT NULL DEFAULT 0,\n     surprise TEXT\n")
            .also { check(it != withCommitAttempts) }
        raw(path).use { c -> c.createStatement().use { st -> for (ddl in statements(schema)) st.executeUpdate(ddl) } }
        val e = assertFailsWith<IncompatibleDatabase> { Db(path, durable = false) }
        assertTrue("recovery_requests has surprise, which the baseline no longer has" in e.message!!, e.message)
        raw(path).use { c -> assertTrue("recovery_requests.commitAttempts is not in the baseline" in BaselineCatchUp.differences(c)) }
    }

    @Test
    fun aDatabaseMadeBeforeDecoys_startsAndWorks() = startsAndWorks(
        beforeDecoys,
        expectBefore = listOf(
            "table session_chains is missing",
            "recovery_requests.userId is 'userId TEXT NOT NULL REFERENCES users(userId)', the baseline has 'userId TEXT REFERENCES users(userId)'",
            "recovery_requests.commitHash is missing",
            "recovery_requests.cancelledAt is missing",
            "table recovery_mailbox_values is missing",
            "index idx_session_chains_chain is missing",
            "index idx_items_vault_live_size is missing",
            "index idx_recovery_mailbox_values_email is missing",
        ),
        expectAdded = listOf(
            "created table session_chains",
            "rebuilt recovery_requests: its changed userId; adding commitHash, cancelledAt", "created table recovery_mailbox_values",
            "created index idx_items_vault_live_size",
        ),
    )

    /** The rebuild keeps the table's index, and a fresh database needs nothing. */
    @Test
    fun aFreshDatabase_needsNothing_andARebuiltTableKeepsItsIndex() {
        val dir = TestKit.tempDir()
        val path = File(dir, "andvari.db").path
        Db(path, durable = false).use { assertEquals(emptyList<String>(), it.addedAtStart) }
        assertMatchesTheBaseline(path)
        val old = File(dir, "old.db").path
        raw(old).use { c -> c.createStatement().use { st -> for (ddl in statements(beforeDecoys)) st.executeUpdate(ddl) } }
        Db(old, durable = false).close()
        raw(old).use { c ->
            assertEquals(listOf("idx_recovery_requests_user"), c.queryAll("SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='recovery_requests' AND sql IS NOT NULL") { it.getString(1) })
        }
    }

    /**
     * A database lacking a column the step cannot add (NOT NULL without a default; here `users.registeredVia`, as
     * before 15 November 2026) is refused at start with the older-build sentence, and nothing is changed in it: the
     * commit columns it also lacks were not added either (the step runs in the start-up's one transaction).
     */
    @Test
    fun aColumnTheStepCannotAdd_refusesTheStart_andChangesNothing() {
        val path = File(TestKit.tempDir(), "andvari.db").path
        val schema = beforeCommitColumns
            .replace("     registeredVia TEXT NOT NULL CHECK(registeredVia IN ('ticket','link','enrol','setup')),\n", "")
            .replace("CREATE INDEX idx_users_registered ON users(createdAt, registeredVia);\n", "")
        raw(path).use { c -> c.createStatement().use { st -> for (ddl in statements(schema)) st.executeUpdate(ddl) } }
        val e = assertFailsWith<IncompatibleDatabase> { Db(path, durable = false) }
        assertTrue(e.message!!.startsWith("This database was made by an older development build of andvari"), e.message)
        assertTrue("users lacks registeredVia" in e.message!!, e.message)
        raw(path).use { c ->
            assertTrue("recovery_requests.commitHash is missing" in BaselineCatchUp.differences(c))
            assertTrue("users.registeredVia is missing" in BaselineCatchUp.differences(c))
        }
    }

    private suspend fun runAll(client: HttpClient, s: Services, clock: MutableClock, w: World) {
        val me = w.me
        // A password change: it cancels the pending request, which writes recovery_requests.commitHash (and, for one
        // whose code was not entered, recovery_requests.cancelledAt, its state left unverified).
        val pw = """{"currentAuthKey":"${me.authKey}","newAuthKey":"${b32()}",$kdf}"""
        val r1 = client.call(HttpMethod.Put, "/api/v1/account/password", pw, session(s, me.userId, me.deviceId))
        assertEquals(200, r1.status.value, r1.bodyAsText())
        val (st, cancelled) = s.db.read { c -> c.queryOne("SELECT state, cancelledAt FROM recovery_requests WHERE requestId=?", w.requestId) { it.getString(1) to it.longOrNull("cancelledAt") }!! }
        assertTrue(st == "unverified" && cancelled != null, "$st $cancelled")
        // A request for an unknown address stores a decoy row, its userId NULL (since 15 November 2026).
        val decoy = """{"email":"nobody@example.com","rPub":"${b32()}","pollHash":"${sha256Hex(TestKit.crypto.randomBytes(32))}","platform":"android"}"""
        val r2 = client.call(HttpMethod.Post, "/api/v1/recovery/requests", decoy)
        assertEquals(202, r2.status.value, r2.bodyAsText())
        val decoyId = WireJson.json.decodeFromString(RecoveryRequestCreated.serializer(), r2.bodyAsText()).requestId
        assertEquals(listOf<String?>(null), s.db.read { c -> c.queryAll("SELECT userId FROM recovery_requests WHERE requestId=?", decoyId) { it.getString(1) } })
        // Assisted recovery on this private instance: open, verify, the hold, the operator's upload, the commit.
        val poll = TestKit.crypto.randomBytes(32)
        val rPub = b32()
        val open = """{"email":"${me.email}","rPub":"$rPub","pollHash":"${sha256Hex(poll)}","platform":"android"}"""
        val reqId = WireJson.json.decodeFromString(RecoveryRequestCreated.serializer(), client.call(HttpMethod.Post, "/api/v1/recovery/requests", open).bodyAsText()).requestId
        val code = Flow.codeIn(Flow.sink(s).last { it.first == "recovery_request_code" }.third)
        assertEquals(200, client.call(HttpMethod.Post, "/api/v1/recovery/requests/$reqId/verify", """{"code":"$code"}""").status.value)
        clock.advance(Assisted.HOLD_MS)
        val commit = TestKit.crypto.randomBytes(32)
        val sealed = Bytes.toB64(TestKit.crypto.randomBytes(io.silencelen.andvari.core.trust.AnswerToken.sealedBytes(me.email)))
        val commitHash = io.silencelen.andvari.core.trust.AssistedRecovery.commitHash(TestKit.crypto, commit)
        val up = client.call(
            HttpMethod.Post, "/api/v1/admin/recovery-requests/$reqId/fulfil",
            """{"sealed":"$sealed","requestKey":"$rPub","commitHash":"$commitHash","currentAuthKey":"${w.op.authKey}"}""",
            session(s, w.op.userId, w.op.deviceId),
        )
        assertEquals(200, up.status.value, up.bodyAsText())
        val recoveryKey = b32()
        val tail = """$kdf,"newMemberRecovery":{"recoveryWrappedUvk":"AAAA","recoveryAuthKey":"$recoveryKey"},"device":{"platform":"ios","name":"x","deviceSecret":"${b32()}"}"""
        val ac = client.call(HttpMethod.Post, "/api/v1/recovery/requests/$reqId/commit", """{"pollSecret":"${Bytes.toB64(poll)}","commit":"${Bytes.toB64(commit)}","newAuthKey":"${b32()}",$tail}""")
        assertEquals(200, ac.status.value, ac.bodyAsText())
        // A kit-recovery commit with the recovery key the assisted commit set.
        val v = WireJson.json.decodeFromString(
            RecoveryVerifyResponse.serializer(),
            client.call(HttpMethod.Post, "/api/v1/recovery/self/verify", """{"email":"${me.email}","recoveryAuthKey":"$recoveryKey"}""").bodyAsText(),
        )
        val kc = client.call(HttpMethod.Post, "/api/v1/recovery/self/commit", """{"recoveryTicket":"${v.recoveryTicket}","newAuthKey":"${b32()}",$tail}""")
        assertEquals(200, kc.status.value, kc.bodyAsText())
    }
}
