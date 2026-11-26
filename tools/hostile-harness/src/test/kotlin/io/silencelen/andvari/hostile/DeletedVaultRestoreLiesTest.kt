package io.silencelen.andvari.hostile

import io.silencelen.andvari.cli.e2e.doc
import io.silencelen.andvari.cli.e2e.ok
import io.silencelen.andvari.cli.e2e.synced
import io.silencelen.andvari.core.client.items.DeletedVault
import io.silencelen.andvari.core.client.items.ItemResult
import io.silencelen.andvari.core.client.log.LogAction
import io.silencelen.andvari.core.client.net.ResponseCaps
import io.silencelen.andvari.core.model.wire.WireRoute
import io.silencelen.andvari.hostile.proxy.Endless
import io.silencelen.andvari.hostile.proxy.Handler
import io.silencelen.andvari.hostile.proxy.Resp
import io.silencelen.andvari.hostile.proxy.answer
import io.silencelen.andvari.hostile.proxy.refuse
import io.silencelen.andvari.hostile.proxy.set
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Two routes of the last row (the order of what a lie could cost): the owner's "Recently deleted" shared vaults,
 * `GET /vaults/deleted` (spec 03 §11.2; `ItemEngine.deletedVaults`), and the restore of a deleted item,
 * `POST /items/{id}/restore` (spec 03 §5.1; `ItemEngine.restoreDeleted`), both through the headless host.
 */
class DeletedVaultRestoreLiesTest {
    private fun JsonObject.with(key: String, value: String) = set(key, JsonPrimitive(value))

    /** The real list answer passed through [edit]. */
    private fun rows(edit: (List<JsonObject>) -> List<JsonObject>) = Handler { x ->
        val r = x.forward()
        if (!r.ok) r else Resp.json(r.status, JsonArray(edit(Json.parseToJsonElement(r.text).jsonArray.map { it.jsonObject })))
    }

    private val buffered = 16L shl 20

    /**
     * `GET /vaults/deleted` lied to: a row whose id is not a UUID, or whose purge comes before its deletion, is dropped; a
     * row twice is shown once; a row whose sealed name was altered is shown without a name (the name is opened only with
     * the key this device holds, never from the served wrap); a LIVE vault of Alice's served as deleted is shown, but
     * unverified (her log has no `delete`), so nothing the app decides rests on the row alone (W). Another account's
     * deleted vault, one Alice is no member of, has no name and is unverified (A). The list from before the delete
     * withholds the row (R: the device cannot tell, the stated limit). Half the answer (T), another route's answer (O),
     * an endless answer (S, refused at the cap) and `{}`, `ok` or a `500` (X) are failures, never "nothing deleted".
     */
    @Test fun aDeletedVaultsListThatLiesNamesNothingItCannotOpenAndAShapeNeverGivenIsAFailure() = world {
        operator()
        val ah = member("alice")
        val bh = member("bob")
        val a = account(ah)
        val b = account(bh)
        a.synced()
        val gone = a.ok(null, LogAction.Create("Old"))
        val live = a.ok(null, LogAction.Create("Kept"))
        suspend fun deleted() = assertIs<ItemResult.Ok<List<DeletedVault>>>(a.items.deletedVaults()).value
        assertTrue(deleted().isEmpty())
        val before = assertNotNull(proxy.last(WireRoute.VAULTS_DELETED, "alice")?.upstream).text
        a.ok(gone, LogAction.Delete)
        a.synced()
        val honest = deleted().single()
        assertEquals(gone, honest.vaultId)
        assertEquals("Old", honest.name)
        assertTrue(honest.verified)
        val honestRow = Json.parseToJsonElement(assertNotNull(proxy.last(WireRoute.VAULTS_DELETED, "alice")?.upstream).text).jsonArray.single().jsonObject
        // Bob's own deleted vault, which Alice never was a member of.
        b.synced()
        val bobs = b.ok(null, LogAction.Create("Bob's"))
        b.ok(bobs, LogAction.Delete)
        b.synced()
        assertTrue(assertIs<ItemResult.Ok<List<DeletedVault>>>(b.items.deletedVaults()).value.any { it.vaultId == bobs })
        val bobsRow = Json.parseToJsonElement(assertNotNull(proxy.last(WireRoute.VAULTS_DELETED, "bob")?.upstream).text).jsonArray.single { it.jsonObject["vaultId"]!!.jsonPrimitive.content == bobs }.jsonObject
        val mark = proxy.mark()

        suspend fun shown(lie: Handler, what: String): List<DeletedVault> {
            val rule = proxy.on(WireRoute.VAULTS_DELETED, "alice", handler = lie)
            val got = a.items.deletedVaults()
            rule.remove()
            return assertIs<ItemResult.Ok<List<DeletedVault>>>(got, what).value
        }
        assertEquals(listOf(honest), shown(rows { l -> l + l.first().with("vaultId", "not-a-uuid") }, "a row with a bad id (W)"), "dropped")
        assertEquals(listOf(honest), shown(rows { l -> l + bobsRow.set("purgeAt", JsonPrimitive(0L)) }, "a purge before the deletion (W)"))
        assertEquals(listOf(honest), shown(rows { l -> l + l }, "a row twice (W)"))
        val altered = shown(rows { l -> l.map { r -> r.with("metaBlob", r["metaBlob"]!!.jsonPrimitive.content.let { s -> s.substring(0, 10) + (if (s[10] == 'A') "B" else "A") + s.substring(11) }) } }, "the sealed name altered (W)").single()
        assertNull(altered.name, "an altered sealed name opens to nothing")
        val liveShown = shown(rows { l -> l + honestRow.with("vaultId", live) }, "a live vault served as deleted (W)").single { it.vaultId == live }
        assertTrue(!liveShown.verified, "the log has no delete: unverified")
        val other = shown(rows { l -> l + bobsRow }, "Bob's deleted vault (A)").single { it.vaultId == bobs }
        assertNull(other.name, "a vault this device holds no key for is never named from the served wrap")
        assertTrue(!other.verified)
        assertEquals(emptyList(), shown(answer { Resp.json(200, Json.parseToJsonElement(before)) }, "the list before the delete (R): the stated limit"))

        val failures: List<Pair<String, Handler>> = listOf(
            "half the answer, by length (T)" to Handler { x -> val r = x.forward(); Resp(r.status, r.headers, ByteArray(0), Endless.truncated(r.body, r.body.size / 2, true)) },
            "half the answer, chunked (T)" to Handler { x -> val r = x.forward(); Resp(r.status, r.headers, ByteArray(0), Endless.truncated(r.body, r.body.size / 2, false)) },
            "one row, not a list (O)" to answer { Resp.json(200, honestRow) },
            "the deleted items' answer (O)" to answer { Resp.json(200, Json.parseToJsonElement("""{"items":[],"more":false}""")) },
            "an empty object (X)" to answer { Resp.json(200, JsonObject(emptyMap())) },
            "a plain ok (X)" to answer { Resp.ok() },
            "a 500 (X)" to refuse(500, "internal"),
        )
        for ((what, lie) in failures) {
            val rule = proxy.on(WireRoute.VAULTS_DELETED, "alice", handler = lie)
            val got = a.items.deletedVaults()
            rule.remove()
            assertIs<ItemResult.Failed>(got, "$what: a failure, never \"nothing deleted\": $got")
        }
        val cap = ResponseCaps.of(WireRoute.VAULTS_DELETED)
        for (endless in listOf(Endless(declaredLength = 1L shl 40, upTo = cap + (64L shl 20)), Endless(declaredLength = null, upTo = cap + (64L shl 20)))) {
            val at = proxy.mark()
            val rule = proxy.on(WireRoute.VAULTS_DELETED, "alice") { _ -> Resp(200, mapOf("Content-Type" to "application/json"), ByteArray(0), endless) }
            val got = a.items.deletedVaults()
            rule.remove()
            assertIs<ItemResult.Failed>(got, "endless (S): $got")
            for (ex in proxy.since(at).filter { it.req.route == WireRoute.VAULTS_DELETED }) assertTrue(ex.written <= cap + buffered, "took ${ex.written}, cap $cap")
        }
        // Only reads were sent for the list, and the honest list reads as before.
        assertTrue(proxy.requests(tag = "alice", since = mark).all { it.route?.method == "GET" }, "nothing but reads")
        assertEquals(listOf(honest), deleted())
    }

    /**
     * `POST /items/{id}/restore` lied to. Stored, then answered with a revision far below or far above the true one (W),
     * or with an earlier restore's answer (R): the item is back, and the sync after it is in order (the device takes no
     * revision from this answer). Not stored, and answered `ok`, `{}` or a `500` (X): a failure; the item stays in the
     * trash and the next honest restore brings it back.
     */
    @Test fun aRestoreAnswerThatLiesBringsBackNothingTheServerDidNotStoreAndIsNeverAWrongRevision() = world {
        operator()
        val ah = member("alice")
        val a = account(ah)
        a.synced()
        val v = assertNotNull(a.personalVaultId)
        val ids = (1..4).map { n ->
            val (saved, err) = a.putItem(v, doc("item $n"))
            assertEquals(null, err)
            saved!!.itemId
        }
        a.synced()
        for (id in ids) assertEquals(null, a.deleteItem(id).second)
        a.synced()
        val trash = assertIs<ItemResult.Ok<List<io.silencelen.andvari.core.client.DeletedItemView>>>(a.items.deletedItems()).value
        fun docOf(id: String) = assertNotNull(trash.single { it.itemId == id }.doc)
        fun names() = a.items(v).map { it.doc["name"]!!.jsonPrimitive.content }.toSet()

        // An honest restore first, for its answer.
        assertIs<ItemResult.Ok<Unit>>(a.items.restoreDeleted(ids[0], v, docOf(ids[0])))
        val earlier = Json.parseToJsonElement(assertNotNull(proxy.last(WireRoute.ITEM_RESTORE, "alice")?.upstream).text)
        assertTrue("item 1" in names())

        val stored: List<Pair<String, Handler>> = listOf(
            "a revision far below (W)" to Handler { x -> x.forward(); Resp.json(200, Json.parseToJsonElement("""{"rev":1}""")) },
            "a revision far above (W)" to Handler { x -> x.forward(); Resp.json(200, Json.parseToJsonElement("""{"rev":${Long.MAX_VALUE / 2}}""")) },
            "an earlier restore's answer (R)" to Handler { x -> x.forward(); Resp.json(200, earlier) },
        )
        for ((i, pair) in stored.withIndex()) {
            val (what, lie) = pair
            val id = ids[i + 1]
            val rule = proxy.on(WireRoute.ITEM_RESTORE, "alice", handler = lie)
            val got = a.items.restoreDeleted(id, v, docOf(id))
            rule.remove()
            assertIs<ItemResult.Ok<Unit>>(got, what)
            assertTrue("item ${i + 2}" in names(), "$what: the item is back")
            a.synced()
            assertTrue("item ${i + 2}" in names(), "$what: and stays back after the next sync")
        }

        // Not stored: a status or shape the route never gives.
        val (saved, _) = a.putItem(v, doc("item 5"))
        a.synced()
        assertEquals(null, a.deleteItem(saved!!.itemId).second)
        a.synced()
        val five = assertNotNull(assertIs<ItemResult.Ok<List<io.silencelen.andvari.core.client.DeletedItemView>>>(a.items.deletedItems()).value.single { it.itemId == saved.itemId }.doc)
        for ((what, lie) in listOf<Pair<String, Handler>>(
            "a plain ok (X)" to answer { Resp.ok() },
            "an empty object (X)" to answer { Resp.json(200, JsonObject(emptyMap())) },
            "a 500 (X)" to refuse(500, "internal"),
        )) {
            val rule = proxy.on(WireRoute.ITEM_RESTORE, "alice", handler = lie)
            val got = a.items.restoreDeleted(saved.itemId, v, five)
            rule.remove()
            assertIs<ItemResult.Failed>(got, "$what: $got")
            a.synced()
            assertTrue("item 5" !in names(), "$what: nothing restored")
        }
        assertIs<ItemResult.Ok<Unit>>(a.items.restoreDeleted(saved.itemId, v, five))
        assertTrue("item 5" in names())
    }

    /**
     * `POST /items/{id}/purge` ("delete forever", index row 41). Stored, then answered with a revision far below or far
     * above (W) or an earlier purge's answer (R): done, and the item is gone from the trash list (no revision is taken
     * from the answer). Not stored and answered `ok`, `{}` or a `500` (X): a failure, and the item is still in the trash.
     * Not stored and answered as done with a revision (W, not passed on): the device cannot tell at once; the trash list
     * it reads next still shows the item, so the person sees that it was not deleted, and an honest purge then deletes it.
     */
    @Test fun aPurgeAnswerThatLiesNeverHidesAnItemTheServerStillKeeps() = world {
        operator()
        val ah = member("alice")
        val a = account(ah)
        a.synced()
        val v = assertNotNull(a.personalVaultId)
        val ids = (1..6).map { n -> a.putItem(v, doc("purge $n")).first!!.itemId }
        a.synced()
        for (id in ids) assertEquals(null, a.deleteItem(id).second)
        a.synced()
        suspend fun inTrash(id: String) = assertIs<ItemResult.Ok<List<io.silencelen.andvari.core.client.DeletedItemView>>>(a.items.deletedItems()).value.any { it.itemId == id }

        assertIs<ItemResult.Ok<Unit>>(a.items.purgeDeleted(ids[0], v))
        val earlier = Json.parseToJsonElement(assertNotNull(proxy.last(WireRoute.ITEM_PURGE, "alice")?.upstream).text)
        assertTrue(!inTrash(ids[0]))
        for ((i, pair) in listOf<Pair<String, Handler>>(
            "a revision far below (W)" to Handler { x -> x.forward(); Resp.json(200, Json.parseToJsonElement("""{"rev":1}""")) },
            "a revision far above (W)" to Handler { x -> x.forward(); Resp.json(200, Json.parseToJsonElement("""{"rev":${Long.MAX_VALUE / 2}}""")) },
            "an earlier purge's answer (R)" to Handler { x -> x.forward(); Resp.json(200, earlier) },
        ).withIndex()) {
            val (what, lie) = pair
            val rule = proxy.on(WireRoute.ITEM_PURGE, "alice", handler = lie)
            val got = a.items.purgeDeleted(ids[i + 1], v)
            rule.remove()
            assertIs<ItemResult.Ok<Unit>>(got, what)
            a.synced()
            assertTrue(!inTrash(ids[i + 1]), "$what: gone")
        }
        for ((what, lie) in listOf<Pair<String, Handler>>(
            "a plain ok (X)" to answer { Resp.ok() },
            "an empty object (X)" to answer { Resp.json(200, JsonObject(emptyMap())) },
            "a 500 (X)" to refuse(500, "internal"),
        )) {
            val rule = proxy.on(WireRoute.ITEM_PURGE, "alice", handler = lie)
            val got = a.items.purgeDeleted(ids[4], v)
            rule.remove()
            assertIs<ItemResult.Failed>(got, "$what: $got")
            assertTrue(inTrash(ids[4]), "$what: still in the trash")
        }
        val rule = proxy.on(WireRoute.ITEM_PURGE, "alice", handler = answer { Resp.json(200, Json.parseToJsonElement("""{"rev":50}""")) })
        assertIs<ItemResult.Ok<Unit>>(a.items.purgeDeleted(ids[5], v), "done, not stored: the device cannot tell at once")
        rule.remove()
        a.synced()
        assertTrue(inTrash(ids[5]), "the trash list read next still shows it")
        assertIs<ItemResult.Ok<Unit>>(a.items.purgeDeleted(ids[5], v))
        assertTrue(!inTrash(ids[5]))
    }

    /**
     * The most dangerous lie on `POST /items/{id}/restore`: NOT stored, and answered as done with a plausible revision (W,
     * not passed on). The device cannot tell at once (the answer is the route's own shape) and shows the item as back.
     * What it does at the next sync: the server's state is taken, so the item leaves the vault again and is in the trash
     * list again, with its content, and a second restore brings it back for real. Nothing says that the first restore did
     * not happen (the item engine has no notice for it): the stated limit, in the README.
     */
    @Test fun aRestoreAnsweredAsDoneThatTheServerNeverStoredIsUndoneByTheNextSyncAndTheItemIsInTheTrashAgain() = world {
        operator()
        val ah = member("alice")
        val a = account(ah)
        a.synced()
        val v = assertNotNull(a.personalVaultId)
        val (saved, err) = a.putItem(v, doc("kept in the trash"))
        assertEquals(null, err)
        val id = saved!!.itemId
        a.synced()
        assertEquals(null, a.deleteItem(id).second)
        a.synced()
        suspend fun trash() = assertIs<ItemResult.Ok<List<io.silencelen.andvari.core.client.DeletedItemView>>>(a.items.deletedItems()).value
        fun names() = a.items(v).map { it.doc["name"]!!.jsonPrimitive.content }.toSet()
        val content = assertNotNull(trash().single { it.itemId == id }.doc)

        // A revision a little above any this young account has seen: what an honest answer could look like.
        val rule = proxy.on(WireRoute.ITEM_RESTORE, "alice", handler = answer { Resp.json(200, Json.parseToJsonElement("""{"rev":50}""")) })
        val got = a.items.restoreDeleted(id, v, content)
        rule.remove()
        assertIs<ItemResult.Ok<Unit>>(got, "the device cannot tell at once")
        assertEquals(0, proxy.last(WireRoute.ITEM_RESTORE, "alice")!!.forwards, "the server never saw it")

        a.synced()
        assertTrue("kept in the trash" !in names(), "after the next sync the item is not shown as restored")
        assertEquals(id, trash().singleOrNull { it.itemId == id }?.itemId, "and it is in the trash list again")
        assertIs<ItemResult.Ok<Unit>>(a.items.restoreDeleted(id, v, content))
        a.synced()
        assertTrue("kept in the trash" in names(), "an honest restore then brings it back")
    }
}
