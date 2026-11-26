package io.silencelen.andvari.server

import io.ktor.client.HttpClient
import io.ktor.client.statement.HttpResponse
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpMethod
import io.ktor.server.testing.testApplication
import io.silencelen.andvari.core.model.wire.MutationStatus
import io.silencelen.andvari.core.model.wire.WireJson
import io.silencelen.andvari.core.trust.LogEntry
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull

/**
 * A vault's `delete` may name the point up to which its caller read the vault's items (spec 03 §10.3, `itemsAtMost`):
 * the server refuses it, `409 vault_items_moved`, in the transaction that would store it, when any item row of the vault,
 * live or in the trash, changed after that point. A member's save that lands between a client's read of a vault and the
 * client's deletion of it is then never deleted with the vault unread.
 */
class VaultDeleteReadPointTest {
    private val post = HttpMethod.Post

    /** The rev of a sync of [me]: the point up to which that read saw every item row it may see. */
    private suspend fun HttpClient.readPoint(me: Me): Long {
        val r = call(HttpMethod.Get, "/api/v1/sync?since=0", token = me.token)
        assertEquals(200, r.status.value, r.bodyAsText())
        return WireJson.json.parseToJsonElement(r.bodyAsText()).jsonObject["rev"]!!.jsonPrimitive.long
    }

    private suspend fun HttpClient.postDelete(me: Me, vaultId: String, frame: String, point: String?): HttpResponse =
        call(post, "/api/v1/vaults/$vaultId/log", """{"entry":"$frame"${point?.let { ""","itemsAtMost":$it""" } ?: ""}}""", me.token)

    private fun deletedAt(s: Services, vaultId: String): Long? =
        s.db.read { db -> db.queryOne("SELECT deletedAt FROM vaults WHERE vaultId=?", vaultId) { it.longOrNull("deletedAt") } }

    private fun logSeq(s: Services, vaultId: String): Long =
        s.db.read { db -> db.queryOne("SELECT logSeq FROM vaults WHERE vaultId=?", vaultId) { it.getLong(1) }!! }

    /**
     * Two writers: the owner reads the vault (one copy of its own in it), a member saves an item of their own, and then
     * the owner's deletion arrives naming the read. The deletion is refused and nothing of it is stored: the vault is not
     * deleted, its log did not move, the member's item is there and the member can still save. After a fresh read the
     * same signed entry, with the new point, is stored.
     */
    @Test
    fun aMembersSaveBetweenTheReadAndTheDeletion_refusesTheDeletion_andTheItemStays() = testApplication {
        val s = TestKit.services()
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        val alice = Flow.member(c, s, "alice@example.com")
        val bob = Flow.member(c, s, "bob@example.com")
        val v = SharedVault(c, s, alice).create()
        v.add(bob)
        assertEquals(MutationStatus.APPLIED, c.putItem(alice, v.vaultId).status)

        val read = c.readPoint(alice)
        // The member's save lands after the read and before the deletion.
        val bobsItem = uuid()
        assertEquals(MutationStatus.APPLIED, c.putItem(bob, v.vaultId, itemId = bobsItem).status)

        val frame = v.sign(alice, LogEntry.Delete(v.vaultId, v.next, v.head, alice.userId, v.at, b16()))
        val seqBefore = logSeq(s, v.vaultId)
        val refused = c.postDelete(alice, v.vaultId, frame, read.toString())
        assertEquals(409, refused.status.value, refused.bodyAsText())
        assertEquals(VaultLogs.VAULT_ITEMS_MOVED, refused.errorCode())
        assertNull(deletedAt(s, v.vaultId), "the vault is not deleted")
        assertEquals(seqBefore, logSeq(s, v.vaultId), "the log did not move")
        val row = s.db.read { db -> Items.byId(db, bobsItem) }
        assertNotNull(row, "the member's item is still there")
        assertEquals(false, row.deleted)
        assertNull(s.db.read { db -> VaultLogs.grant(db, bob.userId, v.vaultId)!!.revokedAt }, "the member keeps the vault")
        assertEquals(MutationStatus.APPLIED, c.putItem(bob, v.vaultId).status, "and can still save into it")

        // The client reads again; the same signed entry, beside the new point, is stored.
        val again = c.readPoint(alice)
        val stored = c.postDelete(alice, v.vaultId, frame, again.toString())
        assertEquals(200, stored.status.value, stored.bodyAsText())
        assertNotNull(deletedAt(s, v.vaultId))
    }

    /**
     * Every change of an item row after the read refuses the deletion: a new item, an edit, a conflicting put, a move into
     * the trash, a restore from it. A purge after the read does not: it removes a row that was already in the trash, and
     * the deletion loses nothing by it. A read point at or above every row's rev stores the deletion.
     */
    @Test
    fun everyChangeOfAnItemRowAfterTheRead_refuses_aPurgeDoesNot() = testApplication {
        val s = TestKit.services()
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        val alice = Flow.member(c, s, "alice@example.com")
        val bob = Flow.member(c, s, "bob@example.com")
        val v = SharedVault(c, s, alice).create()
        v.add(bob)
        val frame = v.sign(alice, LogEntry.Delete(v.vaultId, v.next, v.head, alice.userId, v.at, b16()))
        val item = uuid()
        var rev = c.putItem(bob, v.vaultId, itemId = item).newItemRev!!
        val purged = uuid()
        val purgedRev = c.putItem(bob, v.vaultId, itemId = purged).newItemRev!!
        c.deleteItem(bob, v.vaultId, purged, purgedRev)

        suspend fun refusedAfter(what: String, change: suspend () -> Unit) {
            val read = c.readPoint(alice)
            change()
            val r = c.postDelete(alice, v.vaultId, frame, read.toString())
            assertEquals(409, r.status.value, "$what: ${r.bodyAsText()}")
            assertEquals(VaultLogs.VAULT_ITEMS_MOVED, r.errorCode(), what)
            assertNull(deletedAt(s, v.vaultId), what)
        }
        refusedAfter("a new item") { c.putItem(bob, v.vaultId) }
        refusedAfter("an edit") { rev = c.putItem(bob, v.vaultId, itemId = item, base = rev).newItemRev!! }
        refusedAfter("a conflicting put") {
            val r = c.putItem(bob, v.vaultId, itemId = item, base = 0)
            assertEquals(MutationStatus.CONFLICT, r.status)
            rev = r.newItemRev!!
        }
        refusedAfter("a move into the trash") { assertEquals(MutationStatus.APPLIED, c.deleteItem(bob, v.vaultId, item, rev).status) }
        refusedAfter("a restore") {
            val r = c.call(post, "/api/v1/items/$item/restore", """{"formatVersion":2,"attachmentIds":[],"blob":"QUJD"}""", bob.token)
            assertEquals(200, r.status.value, r.bodyAsText())
        }

        // The purge of an item already in the trash moves no rev: the deletion read before it is stored.
        val read = c.readPoint(alice)
        val p = c.call(post, "/api/v1/items/$purged/purge", token = bob.token)
        assertEquals(200, p.status.value, p.bodyAsText())
        val r = c.postDelete(alice, v.vaultId, frame, read.toString())
        assertEquals(200, r.status.value, r.bodyAsText())
        assertNotNull(deletedAt(s, v.vaultId))
    }

    /** A read point no item row is above: the deletion is stored unless something else refuses it. */
    private val everything = "9007199254740991"

    /** The calls counted in [me]'s device window and in its account's ceiling of `vault_destructive`. */
    private fun destructiveDraws(s: Services, userId: String, deviceId: String): Pair<Int, Int> =
        s.limiter.count(Bucket.deviceKey(SharedBuckets.VAULT_DESTRUCTIVE, deviceId)) to
            s.limiter.count(Bucket.accountKey(SharedBuckets.VAULT_DESTRUCTIVE, userId))

    private fun destructiveDraws(s: Services, me: Me): Pair<Int, Int> = destructiveDraws(s, me.userId, me.deviceId)

    /**
     * A deletion refused because the vault's items moved on gives its draw on `vault_destructive` (10 an hour per device)
     * back: the caller did nothing wrong and nothing was stored. A client that reads, tries, is refused and tries again
     * more often than the limit allows still has its deletion taken. The account's ceiling (40 an hour) keeps each try.
     */
    @Test
    fun refusalsBecauseTheItemsMoved_giveTheirDrawBack_moreThanTheLimit_thenTheDeletionIsTaken() = testApplication {
        val s = TestKit.services()
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        val alice = Flow.member(c, s, "alice@example.com")
        val v = SharedVault(c, s, alice).create()
        // An item whose rev is above the point 0: every try naming 0 is refused.
        assertEquals(MutationStatus.APPLIED, c.putItem(alice, v.vaultId).status)
        val frame = v.sign(alice, LogEntry.Delete(v.vaultId, v.next, v.head, alice.userId, v.at, b16()))
        val limit = SharedBuckets.VAULT_DESTRUCTIVE.limit
        repeat(limit + 5) { i ->
            val r = c.postDelete(alice, v.vaultId, frame, "0")
            assertEquals(409, r.status.value, "try ${i + 1}: ${r.bodyAsText()}")
            assertEquals(VaultLogs.VAULT_ITEMS_MOVED, r.errorCode(), "try ${i + 1}")
        }
        assertEquals(0 to limit + 5, destructiveDraws(s, alice), "the device's window holds none of the tries; the ceiling holds each")
        assertNull(deletedAt(s, v.vaultId))
        val stored = c.postDelete(alice, v.vaultId, frame, everything)
        assertEquals(200, stored.status.value, stored.bodyAsText())
        assertNotNull(deletedAt(s, v.vaultId))
        assertEquals(1, destructiveDraws(s, alice).first, "a stored deletion keeps its draw")
    }

    /**
     * The limit still holds for deletions that are stored: with a refusal for moved items between each, ten deletions (each
     * undone by a restore, which draws on another budget) are stored, and the eleventh is `429` whatever its point. The
     * refusal for a moved log is not given back: it stays counted, as it was.
     */
    @Test
    fun storedDeletionsKeepTheirDraw_theLimitHolds_andAMovedLogStaysCounted() = testApplication {
        val s = TestKit.services()
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        val alice = Flow.member(c, s, "alice@example.com")
        val v = SharedVault(c, s, alice).create()
        assertEquals(MutationStatus.APPLIED, c.putItem(alice, v.vaultId).status)
        val limit = SharedBuckets.VAULT_DESTRUCTIVE.limit
        repeat(limit) { i ->
            val deleteId = b16()
            val del = LogEntry.Delete(v.vaultId, v.next, v.head, alice.userId, v.at, deleteId)
            val refused = c.postDelete(alice, v.vaultId, v.sign(alice, del), "0")
            assertEquals(VaultLogs.VAULT_ITEMS_MOVED, refused.errorCode(), "round ${i + 1}: ${refused.bodyAsText()}")
            v.ok(alice, del, ""","itemsAtMost":$everything""")
            assertNotNull(deletedAt(s, v.vaultId), "round ${i + 1}")
            v.ok(alice, LogEntry.Restore(v.vaultId, v.next, v.head, alice.userId, v.at, deleteId))
        }
        assertEquals(limit, destructiveDraws(s, alice).first)
        val eleventh = c.postDelete(alice, v.vaultId, v.sign(alice, LogEntry.Delete(v.vaultId, v.next, v.head, alice.userId, v.at, b16())), everything)
        assertEquals(429, eleventh.status.value, eleventh.bodyAsText())
        assertEquals("rate_limited", eleventh.errorCode())
        assertNull(deletedAt(s, v.vaultId))

        // Another device of hers: refusals for a moved log (a stale `seq`) are counted, and the eleventh is `429`.
        val other = c.login(alice)
        val stale = v.sign(alice, LogEntry.Delete(v.vaultId, v.seq, v.head, alice.userId, v.at, b16()))
        suspend fun postStale() = c.call(post, "/api/v1/vaults/${v.vaultId}/log", """{"entry":"$stale","itemsAtMost":$everything}""", other.accessToken)
        repeat(limit) { i ->
            val r = postStale()
            assertEquals("log_head_moved", r.errorCode(), "stale ${i + 1}: ${r.bodyAsText()}")
        }
        assertEquals(limit, destructiveDraws(s, alice.userId, other.deviceId).first)
        assertEquals("rate_limited", postStale().errorCode())
    }

    /**
     * The field's grammar and where it may ride: anything but a whole JSON number from 0 below 2^53 is `400
     * bad_items_at_most`, on any other kind it is `400 bad_request`, `null` is no point. Without a point the deletion is
     * taken as before (a person's own deletion of a vault needs none). A retry of a stored deletion is answered `200`
     * whatever point it carries, so a client whose answer was lost is never told "not stored" of a stored deletion.
     */
    @Test
    fun thePointsGrammar_noPointIsAsBefore_andARetryOfAStoredDeletionIsNeverRefused() = testApplication {
        val s = TestKit.services()
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        val alice = Flow.member(c, s, "alice@example.com")
        val bob = Flow.member(c, s, "bob@example.com")
        val v = SharedVault(c, s, alice).create()
        val frame = v.sign(alice, LogEntry.Delete(v.vaultId, v.next, v.head, alice.userId, v.at, b16()))
        for (bad in listOf("-1", "1.5", "1e3", "\"5\"", "true", "[]", "9007199254740992")) {
            val r = c.postDelete(alice, v.vaultId, frame, bad)
            assertEquals(400, r.status.value, "$bad: ${r.bodyAsText()}")
            assertEquals("bad_items_at_most", r.errorCode(), bad)
        }
        // On another kind (an add) the point is refused like a side field that kind does not take.
        s.db.tx { writeConnection(it, alice.userId, bob.userId, s.clock.now()) }
        val add = v.sign(alice, LogEntry.Add(v.vaultId, v.next, v.head, alice.userId, v.at, bob.userId, bob.identity.identityPubB64, io.silencelen.andvari.core.trust.MemberRole.WRITER, b16()))
        val onAdd = c.call(post, "/api/v1/vaults/${v.vaultId}/log", """{"entry":"$add","grant":"AAAA","itemsAtMost":0}""", alice.token)
        assertEquals(400, onAdd.status.value, onAdd.bodyAsText())
        assertEquals("bad_request", onAdd.errorCode())
        assertNull(deletedAt(s, v.vaultId))

        // No point (here `null`): an item newer than anything read does not matter, as before.
        c.putItem(alice, v.vaultId)
        val stored = c.postDelete(alice, v.vaultId, frame, "null")
        assertEquals(200, stored.status.value, stored.bodyAsText())
        assertNotNull(deletedAt(s, v.vaultId))
        val head = stored.bodyAsText()
        // The retry of the stored deletion, with a point every row is above, is the byte-identical retry: 200.
        val retry = c.postDelete(alice, v.vaultId, frame, "0")
        assertEquals(200, retry.status.value, retry.bodyAsText())
        assertEquals(
            WireJson.json.parseToJsonElement(head).jsonObject["head"],
            WireJson.json.parseToJsonElement(retry.bodyAsText()).jsonObject["head"],
        )
    }
}
