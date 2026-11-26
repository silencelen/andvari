package io.silencelen.andvari.server

import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpMethod
import io.ktor.server.testing.testApplication
import io.silencelen.andvari.core.model.wire.DeletedItem
import io.silencelen.andvari.core.model.wire.DeletedItemsResponse
import io.silencelen.andvari.core.model.wire.WireJson
import java.util.UUID
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Spec 03 §5.1: the trash list comes in pages of at most 65,536 tombstones, newest first in `(deletedAt, itemId)`
 * descending order, the next page after `?after=<deletedAt>:<itemId>` of the last row. Deletions count against no
 * quota, so without pages an honest answer could pass the 8 MiB a client reads (§0.4).
 */
class TrashPageTest {
    private val get = HttpMethod.Get

    @Test
    fun theTrashListComesInPagesThatAlwaysFitTheClientsCap() = testApplication {
        val s = TestKit.services()
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        val me = Flow.member(c, s, "me@example.com")
        // One more tombstone than a page holds, plus three, in three shared instants so ties cross the page boundary.
        val total = DELETED_PAGE_ROWS + 4
        val base = s.clock.now() - 1_000
        s.db.tx { db ->
            db.prepareStatement(
                "INSERT INTO items(itemId,vaultId,rev,createdAt,updatedAt,deleted,formatVersion,blob) VALUES(?,?,?,?,?,1,1,NULL)",
            ).use { st ->
                for (i in 0 until total) {
                    st.setString(1, UUID.randomUUID().toString()); st.setString(2, me.personalVaultId); st.setLong(3, i + 1L)
                    st.setLong(4, base); st.setLong(5, base + i % 3)
                    st.addBatch()
                }
                st.executeBatch()
            }
        }

        suspend fun page(query: String): List<DeletedItem> {
            val r = c.call(get, "/api/v1/items/deleted$query", token = me.token)
            assertEquals(200, r.status.value)
            val body = r.bodyAsText()
            assertTrue(body.encodeToByteArray().size <= 8_388_608, "a page is ${body.encodeToByteArray().size} bytes")
            return WireJson.json.decodeFromString(DeletedItemsResponse.serializer(), body).items
        }
        fun cursor(d: DeletedItem) = "?after=${d.deletedAt}:${d.itemId}"

        val first = page("")
        assertEquals(DELETED_PAGE_ROWS, first.size)
        val second = page(cursor(first.last()))
        assertEquals(4, second.size)
        assertEquals(emptyList(), page(cursor(second.last())))
        val all = first + second
        assertEquals(total, all.map { it.itemId }.toSet().size, "every tombstone exactly once")
        val keyed = all.map { it.deletedAt to it.itemId }
        assertEquals(keyed.sortedWith(compareBy<Pair<Long, String>>({ it.first }, { it.second }).reversed()), keyed, "newest first")
        // A cursor that is not `<digits>:<uuid>` is refused.
        for (bad in listOf("?after=x", "?after=12", "?after=:${first.last().itemId}", "?after=1x:${first.last().itemId}", "?after=1:nope")) {
            assertEquals("bad_request", c.call(get, "/api/v1/items/deleted$bad", token = me.token).errorCode(), bad)
        }
    }
}
