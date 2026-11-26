package io.silencelen.andvari.cli

import io.silencelen.andvari.cli.e2e.TestServer
import io.silencelen.andvari.core.model.wire.WireRoute
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * The audit log is served in pages of at most [AUDIT_PAGE_ROWS] rows, newest first, the next
 * page by `after=<the last row's id>`. `operator audit` reads one page and says when older rows exist and how to read
 * them; `--after` reads them; `--all` follows the pages up to [AUDIT_MAX_PAGES]; `--json` says the same. A page that is
 * not a page as asked for is refused whole. The pages come from a server in front of the real one that serves a log of
 * [total] rows by the protocol's own paging, read from each request's query.
 */
class AuditPagesTest {
    @Volatile private var total = 1203L
    @Volatile private var lieAbout: ((Long?, List<Long>) -> List<Long>)? = null

    private fun row(id: Long): JsonElement = buildJsonObject {
        put("id", JsonPrimitive(id)); put("at", JsonPrimitive(1_700_000_000_000 + id)); put("type", JsonPrimitive("sign_in"))
    }

    /** The page the protocol serves for the query of [request]: the rows below its `after` (or all), newest first. */
    private fun page(request: String): JsonElement {
        val after = Regex("[?&]after=(\\d+)").find(request)?.groupValues?.get(1)?.toLong()
        val ids = (minOf(total, (after ?: (total + 1)) - 1) downTo 1L).take(AUDIT_PAGE_ROWS)
        return JsonArray((lieAbout?.invoke(after, ids) ?: ids).map(::row))
    }

    private fun ids(out: String): List<Long> = out.lines().filter { it.isNotBlank() }.map { it.substringAfterLast("  id ").toLong() }

    @Test fun oneAPageWhatIsOlderAndHowToReadItAndEveryPageUpToTheCap() {
        TestServer().use { s -> LyingProxy(s).use { p ->
            val w = CliWorld(s)
            p.lie = mapOf(WireRoute.ADMIN_AUDIT to { _ -> page(p.seen.last()) })
            fun audit(vararg args: String) = w.run(w.op, "operator", "audit", *args, dial = p.address)

            // One page: the newest 500, and the words that say older rows exist and how to read them.
            val first = audit().ok()
            assertEquals((1203L downTo 704L).toList(), ids(first))
            val one = audit()
            assertTrue(one.err.contains("older rows exist") && one.err.contains("--after 704") && one.err.contains("--all"), one.err)
            // --after: the next page, with the cursor sent.
            assertEquals((703L downTo 204L).toList(), ids(audit("--after", "704").ok()))
            assertTrue(p.seen.last().contains("after=704"), p.seen.last())
            // --all: every page; the last is not full, so nothing more is said.
            val all = audit("--all")
            assertEquals((1203L downTo 1L).toList(), ids(all.ok()))
            assertFalse(all.err.contains("older rows exist"), all.err)
            // The machine-readable form says the same.
            val j1 = Json.parseToJsonElement(audit("--json").ok()).jsonObject
            assertEquals(500, j1.getValue("rows").jsonArray.size)
            assertEquals(true, j1.getValue("more").jsonPrimitive.boolean)
            assertEquals(704L, j1.getValue("after").jsonPrimitive.long)
            val jAll = Json.parseToJsonElement(audit("--all", "--json").ok()).jsonObject
            assertEquals(1203, jAll.getValue("rows").jsonArray.size)
            assertEquals(false, jAll.getValue("more").jsonPrimitive.boolean)
            assertEquals(JsonNull, jAll.getValue("after"))
            assertEquals(2, audit("--after", "first").code)

            // The cap: --all stops after AUDIT_MAX_PAGES pages and says where to go on from.
            total = AUDIT_PAGE_ROWS * (AUDIT_MAX_PAGES + 1L) + 7
            val capped = audit("--all")
            val capIds = ids(capped.ok())
            assertEquals(AUDIT_PAGE_ROWS * AUDIT_MAX_PAGES, capIds.size)
            assertTrue(capped.err.contains("Stopped after $AUDIT_MAX_PAGES pages") && capped.err.contains("--after ${capIds.last()}"), capped.err)
            val jCap = Json.parseToJsonElement(audit("--all", "--json").ok()).jsonObject
            assertEquals(true, jCap.getValue("more").jsonPrimitive.boolean)
            assertEquals(capIds.last(), jCap.getValue("after").jsonPrimitive.long)

            // Pages that are not pages as asked for: refused whole, nothing shown, with --json nothing printed.
            total = 1203
            val lies = listOf<Pair<String, (Long?, List<Long>) -> List<Long>>>(
                "a later page that starts at or above its cursor" to { after, ids -> if (after != null) listOf(after) + ids.drop(1) else ids },
                "a page out of order" to { _, ids -> ids.reversed() },
                "a page that holds a row twice" to { _, ids -> ids.take(10) + ids.take(10) },
                "a page of more than 500 rows" to { _, ids -> ids + (ids.last() - 1 downTo maxOf(1, ids.last() - 5)) },
            )
            for ((what, lie) in lies) {
                lieAbout = lie
                for (args in listOf(listOf("--all"), listOf("--all", "--json"))) {
                    val r = audit(*args.toTypedArray())
                    assertEquals(EXIT_SERVER_ANSWER, r.code, "$what: ${r.err}")
                    assertTrue(r.err.contains("[$KEY_SERVER_ROW_REFUSED]"), "$what: ${r.err}")
                    assertEquals("", r.out, what)
                }
            }
        } }
    }
}
