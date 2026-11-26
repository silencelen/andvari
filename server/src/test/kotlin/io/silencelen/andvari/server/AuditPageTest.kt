package io.silencelen.andvari.server

import io.ktor.client.HttpClient
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpMethod
import io.ktor.server.testing.testApplication
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.model.wire.AuditRow
import io.silencelen.andvari.core.model.wire.EscrowUpload
import io.silencelen.andvari.core.model.wire.WireJson
import kotlinx.serialization.builtins.ListSerializer
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Spec 03 §7.3, index row 82: the audit list is served in pages of at most 500, newest first,
 * `?after=<id>` of the previous page's last row starting the next; the filters stay the server's. And a read of a
 * recovery copy for an account that does not exist writes no row.
 */
class AuditPageTest {
    private val get = HttpMethod.Get
    private val post = HttpMethod.Post

    private suspend fun page(c: HttpClient, token: String, query: String): List<AuditRow> {
        val r = c.call(get, "/api/v1/admin/audit${if (query.isEmpty()) "" else "?$query"}", token = token)
        assertEquals(200, r.status.value, r.bodyAsText())
        return WireJson.json.decodeFromString(ListSerializer(AuditRow.serializer()), r.bodyAsText())
    }

    /** Every page for [filters], as a client reads them: while a page holds 500 rows, ask again after its last id. */
    private suspend fun all(c: HttpClient, s: Services, token: String, filters: String): List<List<AuditRow>> {
        val pages = ArrayList<List<AuditRow>>()
        var after: Long? = null
        while (true) {
            s.limiter.clear()
            val q = listOfNotNull(filters.ifEmpty { null }, after?.let { "after=$it" }).joinToString("&")
            val p = page(c, token, q)
            pages += p
            if (p.size < 500) return pages
            after = p.last().id
            assertTrue(pages.size < 10, "the pages must end")
        }
    }

    @Test
    fun theReviewersProbe_anEscrowReadBehind600LaterRows_isOnTheSecondPage() = testApplication {
        val key = TestKit.Identity().curvePub
        val s = TestKit.services(TestKit.config(recoveryKey = key))
        application { andvariModule(s) }
        val c = client
        val op = Flow.finishSetup(c, s)
        val me = Me("me@example.com")
        Flow.register(c, s, me, Flow.enrolAuth(s), "operator", Flow.escrow(me, sha256Hex(key)))
        // A real read of the copy writes its row.
        val read = c.call(post, "/api/v1/admin/accounts/${me.userId}/escrow", """{"currentAuthKey":"${op.authKey}"}""", op.token)
        assertEquals(200, read.status.value, read.bodyAsText())
        assertEquals(1L, s.db.read { it.count("SELECT COUNT(*) FROM audit WHERE type='operator_escrow_read'") })
        // 600 later rows, two types.
        s.db.tx { db -> repeat(600) { i -> s.audit.on(db, if (i % 2 == 0) "test_even" else "test_odd", null, null, null, "n=$i") } }
        val total = s.db.read { it.count("SELECT COUNT(*) FROM audit") }

        val pages = all(c, s, op.token, "since=0")
        assertEquals(listOf(500, (total - 500).toInt()), pages.map { it.size })
        val rows = pages.flatten()
        assertEquals(total, rows.size.toLong())
        assertEquals(rows.map { it.id }.sortedDescending(), rows.map { it.id }, "newest first, across the pages")
        assertEquals(rows.size, rows.map { it.id }.toSet().size, "no row twice")
        assertTrue(pages[0].none { it.type == "operator_escrow_read" }, "the first page is full of the later rows")
        assertTrue(pages[1].any { it.type == "operator_escrow_read" }, "the second page reaches it")

        // The filters stay the server's on every page.
        val odd = all(c, s, op.token, "type=test_odd").flatten()
        assertEquals(300, odd.size); assertTrue(odd.all { it.type == "test_odd" })
        val evens = all(c, s, op.token, "type=test_even&since=0")
        assertEquals(listOf(300), evens.map { it.size })
        // A page that ends exactly on the last row is followed by an empty one.
        s.db.tx { db -> repeat(200) { s.audit.on(db, "test_odd", null, null, null) } }
        assertEquals(listOf(500, 0), all(c, s, op.token, "type=test_odd").map { it.size })
    }

    @Test
    fun aMalformedCursorOrType_isRefused() = testApplication {
        val s = TestKit.services()
        application { andvariModule(s) }
        val c = client
        val op = Flow.finishSetup(c, s)
        for (q in listOf("after=0", "after=-1", "after=abc", "after=01", "after=", "after=1.5", "after=${"9".repeat(17)}")) {
            s.limiter.clear()
            val r = c.call(get, "/api/v1/admin/audit?$q", token = op.token)
            assertEquals(400, r.status.value, q); assertEquals("bad_request", r.errorCode(), q)
        }
        for (q in listOf("type=", "type=Login", "type=login%20fail", "type=${"a".repeat(65)}")) {
            s.limiter.clear()
            val r = c.call(get, "/api/v1/admin/audit?$q", token = op.token)
            assertEquals(400, r.status.value, q); assertEquals("bad_type", r.errorCode(), q)
        }
        // A cursor past every row is the first page; one below every row is an empty page.
        s.limiter.clear()
        assertTrue(page(c, op.token, "after=${Long.MAX_VALUE shr 12}").isNotEmpty())
        assertEquals(emptyList(), page(c, op.token, "after=1"))
    }

    @Test
    fun anEscrowReadOfAnAccountThatDoesNotExist_writesNoRow() = testApplication {
        val key = TestKit.Identity().curvePub
        val s = TestKit.services(TestKit.config(recoveryKey = key))
        application { andvariModule(s) }
        val c = client
        val op = Flow.finishSetup(c, s)
        val before = s.db.read { it.count("SELECT COUNT(*) FROM audit") }
        for (id in listOf(uuid(), "not-a-uuid")) {
            s.limiter.clear()
            val r = c.call(post, "/api/v1/admin/accounts/$id/escrow", """{"currentAuthKey":"${op.authKey}"}""", op.token)
            assertEquals(400, r.status.value, r.bodyAsText()); assertEquals("no_such_user", r.errorCode())
        }
        assertEquals(0L, s.db.read { it.count("SELECT COUNT(*) FROM audit WHERE type='operator_escrow_read'") })
        assertEquals(before, s.db.read { it.count("SELECT COUNT(*) FROM audit") })
    }
}
