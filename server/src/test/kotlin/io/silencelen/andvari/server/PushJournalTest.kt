package io.silencelen.andvari.server

import io.ktor.client.HttpClient
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpMethod
import io.ktor.server.testing.testApplication
import io.silencelen.andvari.core.model.wire.WireJson
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Spec 02 §5, spec 03 §5: the push journal holds no vault content, one answer carries each stored
 * item at most once and no more than the push body cap of them, deletes of items that never existed are not
 * journaled, and a device's journal is capped.
 */
class PushJournalTest {
    private val post = HttpMethod.Post

    private fun blobOf(chars: Int, fill: Char) = fill.toString().repeat(chars)

    private suspend fun HttpClient.push(me: Me, muts: List<String>): List<JsonObject> {
        val r = call(post, "/api/v1/sync/push", """{"mutations":${muts.joinToString(",", "[", "]")}}""", me.token)
        assertEquals(200, r.status.value, r.bodyAsText().take(300))
        return WireJson.json.parseToJsonElement(r.bodyAsText()).jsonObject["results"]!!.jsonArray.map { it.jsonObject }
    }

    private fun put(pv: String, id: String, blob: String, base: Long = 0, ids: String = "[]", mid: String = uuid()) =
        """{"mutationId":"$mid","op":"put","itemId":"$id","vaultId":"$pv","baseItemRev":$base,"item":{"formatVersion":2,"attachmentIds":$ids,"blob":"$blob"}}"""

    private fun del(pv: String, id: String, base: Long, mid: String = uuid()) =
        """{"mutationId":"$mid","op":"delete","itemId":"$id","vaultId":"$pv","baseItemRev":$base}"""

    private fun journalText(s: Services): String = s.db.read { c -> c.queryAll("SELECT resultJson FROM mutations") { it.getString(1) } }.joinToString("\n")

    @Test
    fun rejectedPuts_echoTheStoredItemOnce() = testApplication {
        val s = TestKit.services()
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        val me = Flow.member(c, s, "me@example.com")
        val pv = me.personalVaultId
        val id = uuid()
        val stored = blobOf(64 * 1024, 'S')
        c.putItem(me, pv, itemId = id, blob = stored)
        val results = c.push(me, List(Items.BATCH_MAX) { put(pv, id, "QUJD", ids = """["x"]""") })
        assertTrue(results.all { it["status"]!!.jsonPrimitive.content == "rejected" })
        val carrying = results.filter { it["serverItem"] != null }
        assertEquals(1, carrying.size, "the stored item is carried once")
        assertEquals(stored, carrying.single()["serverItem"]!!.jsonObject["blob"]!!.jsonPrimitive.content)
        assertTrue(results.filter { it["serverItem"] == null }.all { it["serverItemOmitted"]?.jsonPrimitive?.content == "true" })
    }

    @Test
    fun staleDeletes_journalNoContent_andAPurgeLeavesNoCopy() = testApplication {
        val s = TestKit.services()
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        val me = Flow.member(c, s, "me@example.com")
        val pv = me.personalVaultId
        val id = uuid()
        val stored = blobOf(64 * 1024, 'T')
        val created = c.putItem(me, pv, itemId = id, blob = stored)
        val results = c.push(me, List(Items.BATCH_MAX) { del(pv, id, 0) })
        assertTrue(results.all { it["status"]!!.jsonPrimitive.content == "conflict" })
        assertEquals(1, results.count { it["serverItem"] != null })
        assertEquals(Items.BATCH_MAX + 1L, s.db.read { it.count("SELECT COUNT(*) FROM mutations") }, "the create and the 200 deletes")
        assertTrue(!journalText(s).contains("TTTT"), "the journal holds no ciphertext")
        assertTrue(journalText(s).length < Items.BATCH_MAX * 400, "the journal rows are small")
        // Delete, then delete forever: no table holds the ciphertext.
        c.deleteItem(me, pv, id, created.newItemRev!!)
        assertEquals(200, c.call(post, "/api/v1/items/$id/purge", null, me.token).status.value)
        val anywhere = s.db.read { db ->
            db.count("SELECT COUNT(*) FROM items WHERE blob LIKE '%TTTT%'") + db.count("SELECT COUNT(*) FROM item_versions WHERE blob LIKE '%TTTT%'") +
                db.count("SELECT COUNT(*) FROM mutations WHERE resultJson LIKE '%TTTT%'")
        }
        assertEquals(0L, anywhere)
    }

    @Test
    fun replayedConflict_readsTheStoredItemAtAnswerTime() = testApplication {
        val s = TestKit.services()
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        val me = Flow.member(c, s, "me@example.com")
        val pv = me.personalVaultId
        // A stale delete: on replay the CURRENT item is carried, not a copy kept from the first answer.
        val id = uuid()
        val r1 = c.putItem(me, pv, itemId = id, blob = "Zmlyc3Q")
        val mid = uuid()
        val first = c.push(me, listOf(del(pv, id, 0, mid))).single()
        assertEquals("Zmlyc3Q", first["serverItem"]!!.jsonObject["blob"]!!.jsonPrimitive.content)
        c.putItem(me, pv, itemId = id, blob = "c2Vjb25k", base = r1.newItemRev!!)
        val again = c.push(me, listOf(del(pv, id, 0, mid))).single()
        assertEquals("conflict", again["status"]!!.jsonPrimitive.content)
        assertEquals(first["newItemRev"]!!.jsonPrimitive.long, again["newItemRev"]!!.jsonPrimitive.long)
        assertEquals("c2Vjb25k", again["serverItem"]!!.jsonObject["blob"]!!.jsonPrimitive.content)
        // A conflicting put: on replay the displaced version comes from the history.
        val id2 = uuid()
        c.putItem(me, pv, itemId = id2, blob = "bG9zaW5n")
        val pmid = uuid()
        val p1 = c.push(me, listOf(put(pv, id2, "d2lubmVy", base = 0, mid = pmid))).single()
        assertEquals("conflict", p1["status"]!!.jsonPrimitive.content)
        val p2 = c.push(me, listOf(put(pv, id2, "d2lubmVy", base = 0, mid = pmid))).single()
        assertEquals(p1["newItemRev"]!!.jsonPrimitive.long, p2["newItemRev"]!!.jsonPrimitive.long)
        assertEquals("bG9zaW5n", p2["serverItem"]!!.jsonObject["blob"]!!.jsonPrimitive.content)
        assertEquals(p1["serverItem"]!!.jsonObject["rev"], p2["serverItem"]!!.jsonObject["rev"])
    }

    @Test
    fun deletesOfItemsThatNeverExisted_areNotJournaled() = testApplication {
        val s = TestKit.services()
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        val me = Flow.member(c, s, "me@example.com")
        val results = c.push(me, List(Items.BATCH_MAX) { del(me.personalVaultId, uuid(), 0) })
        assertTrue(results.all { it["status"]!!.jsonPrimitive.content == "applied" })
        assertEquals(0L, s.db.read { it.count("SELECT COUNT(*) FROM mutations") })
    }

    @Test
    fun journalIsCappedPerDevice() = testApplication {
        val s = TestKit.services()
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        val me = Flow.member(c, s, "me@example.com")
        val pv = me.personalVaultId
        val firstMid = uuid()
        c.push(me, listOf(put(pv, uuid(), "QUJD", mid = firstMid)))
        repeat(6) { c.push(me, List(Items.BATCH_MAX) { put(pv, uuid(), "QUJD") }) }
        assertEquals(Items.JOURNAL_PER_DEVICE.toLong(), s.db.read { it.count("SELECT COUNT(*) FROM mutations WHERE deviceId=?", me.deviceId) })
        assertNull(s.db.read { db -> db.queryOne("SELECT 1 FROM mutations WHERE mutationId=?", firstMid) { 1 } }, "the oldest row went first")
    }

    @Test
    fun echoedItemsAreCappedAtThePushBodyCap() = testApplication {
        val s = TestKit.services()
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        val me = Flow.member(c, s, "me@example.com")
        val pv = me.personalVaultId
        val big = (s.config.itemMaxBytes).toInt()
        val ids = List(5) { uuid() }
        ids.forEachIndexed { i, id -> c.putItem(me, pv, itemId = id, blob = blobOf(big, 'A' + i)) }
        val r = c.call(post, "/api/v1/sync/push", """{"mutations":${ids.joinToString(",", "[", "]") { put(pv, it, "QUJD", ids = """["x"]""") }}}""", me.token)
        assertEquals(200, r.status.value)
        val text = r.bodyAsText()
        assertTrue(text.length <= BODY_CAP_PUSH + 64 * 1024, "answer of ${text.length} bytes")
        val results = WireJson.json.parseToJsonElement(text).jsonObject["results"]!!.jsonArray.map { it.jsonObject }
        val carried = results.count { it["serverItem"] != null }
        assertEquals(3, carried)
        assertEquals(2, results.count { it["serverItemOmitted"]?.jsonPrimitive?.content == "true" && it["serverItem"] == null })
    }

    /**
     * A replayed conflict carries its item only while the account still holds a grant on the vault (spec 03 §5): a member
     * removed from a shared vault who re-sends a journaled conflicting put gets the journaled status and rev, and no blob
     * of that vault. Brought over from the released line's test of the same name.
     */
    @Test
    fun replayAfterTheMemberWasRemoved_carriesNoItem() = testApplication {
        val s = TestKit.services()
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        val owner = Flow.member(c, s, "journal-owner@example.com")
        val member = Flow.member(c, s, "journal-member@example.com")
        // A shared vault with one item of the owner's, and the member added as a writer.
        val vault = SharedVault(c, s, owner).create()
        vault.add(member)
        val id = uuid()
        val ownersValue = blobOf(64, 'O')
        c.putItem(owner, vault.vaultId, itemId = id, blob = ownersValue)

        // The member's stale put conflicts and carries the owner's displaced value; it is journaled by reference.
        val stale = put(vault.vaultId, id, blobOf(64, 'M'))
        val answered = c.push(member, listOf(stale)).single()
        assertEquals("conflict", answered["status"]!!.jsonPrimitive.content)
        assertEquals(ownersValue, answered["serverItem"]!!.jsonObject["blob"]!!.jsonPrimitive.content)
        val again = c.push(member, listOf(stale)).single()
        assertTrue(again["serverItem"] != null, "while a member, the re-send carries the item: $again")

        // Removed from the vault, the member re-sends the same mutation: the journaled outcome, no blob.
        vault.remove(member)
        val replayed = c.push(member, listOf(stale)).single()
        assertEquals("conflict", replayed["status"]!!.jsonPrimitive.content)
        assertTrue(answered["newItemRev"] != null, "$answered")
        assertEquals(answered["newItemRev"], replayed["newItemRev"])
        assertNull(replayed["serverItem"], "no blob of the vault reaches an account removed from it: $replayed")
        assertTrue(!replayed.toString().contains(ownersValue), "nothing of the owner's value: $replayed")
    }
}
