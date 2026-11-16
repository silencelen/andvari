package io.silencelen.andvari.server

import io.ktor.client.request.delete
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.http.contentType
import io.ktor.server.testing.testApplication
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.model.InviteRequest
import io.silencelen.andvari.core.model.InviteResponse
import io.silencelen.andvari.core.model.Mutation
import io.silencelen.andvari.core.model.UserLookupRequest
import io.silencelen.andvari.core.model.UserLookupResponse
import io.silencelen.andvari.core.model.VaultMemberAdd
import io.silencelen.andvari.core.model.MutationResult
import io.silencelen.andvari.core.model.PushResponse
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * A push answer and the push journal stay bounded, and the journal holds no vault content.
 *
 * Before: every rejected put and every stale delete echoed the whole stored item, the item was
 * re-read per mutation, and a stale delete's result (item included) went into `mutations.resultJson`
 * for 180 days, counted in no quota. 200 mutations on one large item in a ~48 KB request built an
 * answer 200 times the item in memory and, in the delete form, wrote it 200 times into the journal.
 */
class PushJournalTest : P4TestSupport() {

    private fun journal(services: Services, userId: String): List<String> =
        services.repo.db.read { c -> c.queryAll("SELECT resultJson FROM mutations WHERE userId=?", userId) { it.getString(1) } }

    /** An item of roughly 64 KiB of ciphertext in the account's personal vault, at rev [PushResponse.rev]. */
    private suspend fun io.ktor.client.HttpClient.bigItem(vc: VirtualClient, itemId: String): Pair<Long, String> {
        val put = putMutation(vc, itemId, "x".repeat(48 * 1024), 0)
        val r = push(vc, put).results.single()
        assertEquals("applied", r.status)
        return r.newItemRev!! to put.item!!.blob
    }

    @Test
    fun rejectedPuts_echoTheStoredItemOnce() = testApplication {
        val services = buildServices(config(), Notifier())
        application { andvariModule(services) }
        val client = jsonClient(this)
        val vc = VirtualClient("echo@x.com", "push journal password")
        client.register(vc, bootstrapToken)
        val itemId = vc.newItemId()
        val (_, blob) = client.bigItem(vc, itemId)

        // 200 puts on that item naming an attachment that does not exist: each is `rejected`.
        val puts = (1..200).map { putMutation(vc, itemId, "y", 1, attachmentIds = listOf(uuid())) }
        val resp = client.pushRaw(vc, *puts.toTypedArray())
        assertEquals(HttpStatusCode.OK, resp.status)
        val text = resp.bodyAsText()
        val results = json.decodeFromString(PushResponse.serializer(), text).results
        assertEquals(200, results.count { it.status == "rejected" })
        assertEquals(1, results.count { it.serverItem != null }, "the stored item is echoed once")
        assertEquals(blob, results.first().serverItem!!.blob, "and that once is the first result's")
        assertTrue(text.length < 3 * blob.length, "answer ${text.length} bytes for a ${blob.length}-byte item")
    }

    @Test
    fun staleDeletes_journalNoContent_andEchoOnce() = testApplication {
        val services = buildServices(config(), Notifier())
        application { andvariModule(services) }
        val client = jsonClient(this)
        val vc = VirtualClient("deletes@x.com", "push journal password")
        client.register(vc, bootstrapToken)
        val itemId = vc.newItemId()
        val (rev, blob) = client.bigItem(vc, itemId)

        val deletes = (1..200).map { Mutation(uuid(), "delete", itemId, vc.personalVaultId, rev - 1, null) }
        val resp = client.pushRaw(vc, *deletes.toTypedArray())
        val text = resp.bodyAsText()
        val results = json.decodeFromString(PushResponse.serializer(), text).results
        assertEquals(200, results.count { it.status == "conflict" })
        assertEquals(1, results.count { it.serverItem != null })
        assertTrue(text.length < 3 * blob.length, "answer ${text.length} bytes for a ${blob.length}-byte item")

        val rows = journal(services, vc.userId!!)
        assertEquals(201, rows.size, "the create and the 200 conflicts are journaled")
        assertTrue(rows.none { it.contains(blob.take(64)) }, "no journal row holds the item's ciphertext")

        // A re-send of one of them answers from the journal, with the item read back now.
        val replay = client.push(vc, deletes[17]).results.single()
        assertEquals("conflict", replay.status)
        assertEquals(blob, replay.serverItem?.blob)
        assertEquals(rev, replay.serverItem?.rev)
    }

    @Test
    fun replayedConflictingPut_returnsTheDisplacedVersion_fromTheHistory() = testApplication {
        val services = buildServices(config(), Notifier())
        application { andvariModule(services) }
        val client = jsonClient(this)
        val vc = VirtualClient("displaced@x.com", "push journal password")
        client.register(vc, bootstrapToken)
        val itemId = vc.newItemId()
        val first = putMutation(vc, itemId, "first value", 0)
        val firstRev = client.push(vc, first).results.single().newItemRev!!
        // A put against a stale rev wins (LWW) and carries the displaced version.
        val second = putMutation(vc, itemId, "second value", 0)
        val answered = client.push(vc, second).results.single()
        assertEquals("conflict", answered.status)
        assertEquals(firstRev, answered.serverItem?.rev)
        assertEquals("first value", vc.decItem(itemId, answered.serverItem!!.blob!!))

        assertTrue(journal(services, vc.userId!!).none { it.contains(first.item!!.blob.take(64)) }, "the journal keeps no blob")
        val replayed = client.push(vc, second).results.single()
        assertEquals(answered.copy(serverItem = answered.serverItem!!.copy(attachmentIds = emptyList())), replayed, "the same answer, read back from the history")
    }

    @Test
    fun deletesOfItemsThatNeverExisted_areNotJournaled_andTheJournalIsCappedPerDevice() = testApplication {
        val services = buildServices(config(), Notifier())
        application { andvariModule(services) }
        val client = jsonClient(this)
        val vc = VirtualClient("cap@x.com", "push journal password")
        client.register(vc, bootstrapToken)

        val ghosts = (1..200).map { Mutation(uuid(), "delete", uuid(), vc.personalVaultId, 0, null) }
        assertTrue(client.push(vc, *ghosts.toTypedArray()).results.all { it.status == "applied" })
        assertEquals(0, journal(services, vc.userId!!).size, "nothing changed, nothing journaled")

        // Deletes of an item already deleted are journaled (the item exists, as a tombstone): six batches of them.
        val itemId = vc.newItemId()
        val rev = client.push(vc, putMutation(vc, itemId, "short", 0)).results.single().newItemRev!!
        client.push(vc, Mutation(uuid(), "delete", itemId, vc.personalVaultId, rev, null))
        val last = (1..6).map { (1..200).map { Mutation(uuid(), "delete", itemId, vc.personalVaultId, rev, null) } }
        last.forEach { batch -> client.push(vc, *batch.toTypedArray()) }
        assertEquals(JOURNAL_PER_DEVICE, journal(services, vc.userId!!).size, "the device keeps its newest $JOURNAL_PER_DEVICE rows")
        // The newest are the ones kept: a re-send of the last batch is answered from the journal.
        val ids = services.repo.db.read { c -> c.queryAll("SELECT mutationId FROM mutations WHERE userId=?", vc.userId!!) { it.getString(1) } }.toSet()
        assertTrue(last.last().all { it.mutationId in ids })
    }

    /**
     * A replayed conflict reads its item's blob only while the account still holds a grant on the vault: a member
     * removed from a shared vault who re-sends a journaled conflicting put gets the journaled status and rev, and no
     * blob of that vault.
     */
    @Test
    fun replayAfterTheMemberWasRemoved_carriesNoItem() = testApplication {
        val services = buildServices(config(), Notifier())
        application { andvariModule(services) }
        val client = jsonClient(this)
        val owner = VirtualClient("journal-owner@x.com", "push journal owner password", fast = true)
        client.register(owner, bootstrapToken)
        val invite = client.post("/api/v1/admin/users") {
            authed(owner); contentType(ContentType.Application.Json); setBody(InviteRequest("journal-member@x.com", isAdmin = false))
        }
        val member = VirtualClient("journal-member@x.com", "push journal member password", fast = true)
        client.register(member, json.decodeFromString(InviteResponse.serializer(), invite.bodyAsText()).inviteToken)

        // A shared vault with one item of the owner's, and the member added as a writer.
        val (createReq, handle) = owner.buildCreateSharedVault()
        assertEquals(HttpStatusCode.Created, client.post("/api/v1/vaults") { authed(owner); contentType(ContentType.Application.Json); setBody(createReq) }.status)
        val itemId = owner.newItemId()
        client.push(owner, Mutation(uuid(), "put", itemId, handle.vaultId, 0, owner.encItemIn(handle.vaultId, handle.vk, itemId, "the owner's value")))
        val lookup = client.post("/api/v1/users/lookup") { authed(owner); contentType(ContentType.Application.Json); setBody(UserLookupRequest(member.email)) }
        val pub = Bytes.fromB64(json.decodeFromString(UserLookupResponse.serializer(), lookup.bodyAsText()).identityPub)
        val add = VaultMemberAdd(member.userId!!, "writer", owner.sealVkFor(pub, handle.vaultId, handle.vk))
        assertEquals(HttpStatusCode.Created, client.post("/api/v1/vaults/${handle.vaultId}/members") { authed(owner); contentType(ContentType.Application.Json); setBody(add) }.status)

        // The member's stale put wins and carries the owner's displaced value; it is journaled by reference.
        val put = Mutation(uuid(), "put", itemId, handle.vaultId, 0, member.encItemIn(handle.vaultId, handle.vk, itemId, "the member's value"))
        val answered = client.push(member, put).results.single()
        assertEquals("conflict", answered.status)
        assertEquals("the owner's value", owner.decItemIn(handle.vaultId, handle.vk, itemId, answered.serverItem!!.blob!!))
        assertNotNull(client.push(member, put).results.single().serverItem, "while a member, the re-send carries the item")

        // Removed from the vault, the member re-sends the same mutation: the journaled outcome, no blob.
        assertEquals(HttpStatusCode.OK, client.delete("/api/v1/vaults/${handle.vaultId}/members/${member.userId}") { authed(owner) }.status)
        val replayed = client.push(member, put).results.single()
        assertEquals("conflict", replayed.status)
        assertEquals(answered.newItemRev, replayed.newItemRev)
        assertNull(replayed.serverItem, "no blob of the vault reaches an account removed from it")
    }

    @Test
    fun aRowWrittenBeforeTheUpgrade_isReplayedVerbatim() = testApplication {
        val services = buildServices(config(), Notifier())
        application { andvariModule(services) }
        val client = jsonClient(this)
        val vc = VirtualClient("legacy@x.com", "push journal password")
        client.register(vc, bootstrapToken)
        val itemId = vc.newItemId()
        val put = putMutation(vc, itemId, "legacy", 0)
        val rev = client.push(vc, put).results.single().newItemRev!!
        val deviceId = services.repo.db.read { c -> c.queryOne("SELECT deviceId FROM devices WHERE userId=?", vc.userId!!) { it.getString(1) } }
        assertNotNull(deviceId)
        val item = services.repo.db.read { c -> services.repo.itemById(c, itemId) }!!
        val legacy = MutationResult(uuid(), "conflict", rev + 1, item)
        services.repo.db.tx { c ->
            c.exec(
                "INSERT INTO mutations(deviceId,mutationId,resultJson,createdAt,userId) VALUES(?,?,?,?,?)",
                deviceId, legacy.mutationId, json.encodeToString(MutationResult.serializer(), legacy), now(), vc.userId!!,
            )
        }
        val replayed = client.push(vc, put.copy(mutationId = legacy.mutationId)).results.single()
        assertEquals(legacy, replayed)
        assertNull(client.push(vc, put).results.single().serverItem, "the applied create replays without an item")
    }
}
