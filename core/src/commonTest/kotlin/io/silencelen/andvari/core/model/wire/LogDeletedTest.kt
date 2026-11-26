package io.silencelen.andvari.core.model.wire

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * `deleted: {deletedAt, purgeAt}` on the log's append and fetch answers (spec 03 §10.3, §10.6): read leniently, so an
 * older server (no field) and a malformed one (a value that is not a pair of whole numbers, or a grace that ends before
 * it began) both read as absent and never fail the answer they ride on.
 */
class LogDeletedTest {
    private val head = """{"seq":3,"hash":"${"a".repeat(64)}","at":7}"""

    private fun page(deleted: String?): LogPage =
        WireJson.json.decodeFromString(LogPage.serializer(), """{"entries":["e"],"head":$head${deleted?.let { ",\"deleted\":$it" } ?: ""}}""")

    private fun appended(deleted: String?): LogAppendResponse =
        WireJson.json.decodeFromString(LogAppendResponse.serializer(), """{"rev":4,"head":$head${deleted?.let { ",\"deleted\":$it" } ?: ""}}""")

    @Test fun theFieldIsReadOnBothAnswers() {
        assertEquals(LogDeleted(1_000, 605_801_000), page("""{"deletedAt":1000,"purgeAt":605801000}""").deleted)
        assertEquals(LogDeleted(1_000, 605_801_000), appended("""{"deletedAt":1000,"purgeAt":605801000}""").deleted)
        assertEquals(LogDeleted(5, 5), page("""{"deletedAt":5,"purgeAt":5}""").deleted, "a grace of zero is still a grace end")
    }

    @Test fun anOlderServerSendsNoFieldAndNothingChanges() {
        val p = page(null)
        assertEquals(null, p.deleted)
        assertEquals(listOf("e"), p.entries)
        assertEquals(null, appended(null).deleted)
        assertEquals(4, appended(null).rev)
    }

    @Test fun aGraceEndBeforeTheDeleteReadsAsAbsent() {
        assertEquals(null, page("""{"deletedAt":2000,"purgeAt":1999}""").deleted)
        assertEquals(null, appended("""{"deletedAt":2000,"purgeAt":0}""").deleted)
    }

    @Test fun valuesThatAreNotWholeNumbersReadAsAbsentAndTheAnswerStillDecodes() {
        val bad = listOf(
            """{"deletedAt":"1000","purgeAt":"2000"}""",
            """{"deletedAt":1000,"purgeAt":"2000"}""",
            """{"deletedAt":1000.5,"purgeAt":2000}""",
            """{"deletedAt":1e3,"purgeAt":2e3}""",
            """{"deletedAt":-1,"purgeAt":2000}""",
            """{"deletedAt":1000,"purgeAt":null}""",
            """{"deletedAt":true,"purgeAt":2000}""",
            """{"deletedAt":1000,"purgeAt":99999999999999999999999}""",
            """{"deletedAt":1000}""",
            """{"deletedAt":{},"purgeAt":[]}""",
            """{}""",
            """null""",
            """[1000,2000]""",
            """"soon"""",
            """17""",
        )
        for (d in bad) {
            val p = page(d)
            assertEquals(null, p.deleted, d)
            assertEquals(3, p.head.seq, "the page itself still decodes: $d")
            assertEquals(null, appended(d).deleted, d)
        }
    }

    @Test fun absentIsNotWritten() {
        val s = WireJson.json.encodeToString(LogPage.serializer(), LogPage(emptyList(), LogHead(0, "a".repeat(64), 0)))
        assertTrue("deleted" !in s, s)
    }
}
