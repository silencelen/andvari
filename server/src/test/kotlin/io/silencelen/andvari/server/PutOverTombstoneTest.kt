package io.silencelen.andvari.server

import io.ktor.client.HttpClient
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpMethod
import io.ktor.server.testing.testApplication
import io.silencelen.andvari.core.model.wire.WireJson
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * A put over a deleted row (spec 03 §5): the item is restored (edit beats delete) and the answer is `conflict` with
 * `serverItem` = the deletion's mark (`deleted: true`, no blob) every time: on the first answer, on a replay of the same
 * `mutationId` (also after the item has left the server), and past the answer's echo cap. The restored row is stored
 * without the conflict mark, since a deletion leaves no version to keep as a copy.
 */
class PutOverTombstoneTest {
    private val post = HttpMethod.Post

    private suspend fun HttpClient.push(me: Me, muts: List<String>): List<JsonObject> {
        val r = call(post, "/api/v1/sync/push", """{"mutations":${muts.joinToString(",", "[", "]")}}""", me.token)
        assertEquals(200, r.status.value, r.bodyAsText().take(300))
        return WireJson.json.parseToJsonElement(r.bodyAsText()).jsonObject["results"]!!.jsonArray.map { it.jsonObject }
    }

    private fun put(pv: String, id: String, blob: String, base: Long = 0, ids: String = "[]", mid: String = uuid()) =
        """{"mutationId":"$mid","op":"put","itemId":"$id","vaultId":"$pv","baseItemRev":$base,"item":{"formatVersion":2,"attachmentIds":$ids,"blob":"$blob"}}"""

    /** A deleted item in [me]'s own vault: its tombstone's rev. */
    private suspend fun HttpClient.tombstone(me: Me, id: String): Long {
        val created = putItem(me, me.personalVaultId, itemId = id)
        return deleteItem(me, me.personalVaultId, id, created.newItemRev!!).newItemRev!!
    }

    private fun JsonObject.mark(): JsonObject {
        assertEquals("conflict", this["status"]!!.jsonPrimitive.content, toString())
        val item = assertNotNull(this["serverItem"] as? JsonObject, "the deletion's mark is served: $this")
        assertEquals("true", item["deleted"]!!.jsonPrimitive.content)
        assertEquals(JsonNull, item["blob"])
        assertEquals(null, this["serverItemOmitted"])
        return item
    }

    @Test
    fun theDeletionsMark_onTheFirstAnswer_onAReplay_andAfterTheItemLeft_andTheRowIsNotMarked() = testApplication {
        val s = TestKit.services()
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        val me = Flow.member(c, s, "me@example.com")
        val pv = me.personalVaultId
        val id = uuid()
        val deletedRev = c.tombstone(me, id)
        val mid = uuid()
        val first = c.push(me, listOf(put(pv, id, "YmFjaw", base = deletedRev, mid = mid))).single()
        val mark = first.mark()
        assertEquals(deletedRev, mark["rev"]!!.jsonPrimitive.long)
        val restored = s.db.read { db -> Items.byId(db, id)!! }
        assertEquals(false, restored.deleted)
        assertEquals(false, restored.conflict, "a deletion leaves no version to copy: the restored row is not marked")
        assertEquals(first["newItemRev"]!!.jsonPrimitive.long, restored.rev)

        // The answer was lost; the device sends again: the same outcome, the same mark.
        val again = c.push(me, listOf(put(pv, id, "YmFjaw", base = deletedRev, mid = mid))).single()
        assertEquals(mark, again.mark())
        assertEquals(first["newItemRev"], again["newItemRev"])

        // The item is deleted again and deleted forever: a replay still names the deletion it displaced.
        c.deleteItem(me, pv, id, restored.rev)
        assertEquals(200, c.call(post, "/api/v1/items/$id/purge", null, me.token).status.value)
        assertEquals(mark, c.push(me, listOf(put(pv, id, "YmFjaw", base = deletedRev, mid = mid))).single().mark())
    }

    @Test
    fun theDeletionsMark_isNeverLeftOutForTheAnswersCap() = testApplication {
        val s = TestKit.services()
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        val me = Flow.member(c, s, "me@example.com")
        val pv = me.personalVaultId
        val big = s.config.itemMaxBytes.toInt()
        val bigIds = List(5) { uuid() }
        bigIds.forEachIndexed { i, id -> c.putItem(me, pv, itemId = id, blob = ('A' + i).toString().repeat(big)) }
        val dead = uuid()
        val deletedRev = c.tombstone(me, dead)
        val mid = uuid()
        // Five rejected puts use the cap up first (three carried, two left out), then the put over the deletion and its
        // replay inside the same batch.
        val results = c.push(
            me,
            bigIds.map { put(pv, it, "QUJD", ids = """["x"]""") } + put(pv, dead, "YmFjaw", base = deletedRev, mid = mid) +
                put(pv, dead, "YmFjaw", base = deletedRev, mid = mid),
        )
        assertEquals(2, results.take(5).count { it["serverItemOmitted"]?.jsonPrimitive?.content == "true" }, "the cap was reached")
        assertEquals(deletedRev, results[5].mark()["rev"]!!.jsonPrimitive.long)
        assertEquals(results[5].mark(), results[6].mark())
        assertTrue(s.db.read { db -> !Items.byId(db, dead)!!.conflict })
    }
}
