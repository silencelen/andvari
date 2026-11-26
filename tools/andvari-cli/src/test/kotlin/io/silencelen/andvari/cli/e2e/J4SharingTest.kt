package io.silencelen.andvari.cli.e2e

import io.silencelen.andvari.core.client.log.LogAction
import io.silencelen.andvari.core.client.log.VaultLogStatus
import kotlinx.serialization.json.jsonPrimitive
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue

/**
 * Journey 4: two accounts connect through a connect link and type each other's code; a shared vault is created, the
 * other is added and accepts; items sync both ways; leave, remove, delete, restore, an ownership offer and its acceptance.
 */
class J4SharingTest {
    @Test fun twoAccountsConnectShareAVaultAndWalkItsLog() {
        TestServer().use { it.journey { val s = this
            Steps.registerThrough(s.device("operator"), s.origin, s.setupLink, "op@example.org")
            val ah = s.device("alice")
            Steps.registerThrough(ah, s.origin, Steps.enrolLink(s), "alice@example.org", trustGate = true)
            val bh = s.device("bob")
            Steps.registerThrough(bh, s.origin, Steps.enrolLink(s), "bob@example.org", trustGate = true)
            connect(ah, bh, s.origin)
            val a = ah.account(s.origin)!!
            val b = bh.account(s.origin)!!

            // Create, add, accept.
            a.synced()
            val v = a.ok(null, LogAction.Create("Family"))
            a.ok(v, LogAction.Add(b.userId, "writer"))
            accept(b, v)

            // Items both ways.
            a.synced()
            assertEquals(null, a.putItem(v, doc("from alice")).second)
            b.synced()
            assertEquals(listOf("from alice"), b.items(v).map { it.doc["name"]!!.jsonPrimitive.content })
            assertEquals(null, b.putItem(v, doc("from bob")).second)
            a.synced()
            assertEquals(setOf("from alice", "from bob"), a.items(v).map { it.doc["name"]!!.jsonPrimitive.content }.toSet())

            // Leave, then a new add and accept, then remove.
            b.ok(v, LogAction.Leave)
            a.synced()
            val afterLeave = assertIs<VaultLogStatus.Verified>(a.logs.status(v))
            assertTrue(b.userId !in afterLeave.state.members)
            a.ok(v, LogAction.Add(b.userId, "reader"))
            accept(b, v)
            a.ok(v, LogAction.Remove(b.userId))
            b.synced()
            assertIs<VaultLogStatus.Removed>(b.logs.status(v), "the removed member sees the removal: ${b.logs.status(v)}")

            // Delete and restore.
            a.ok(v, LogAction.Delete)
            a.synced()
            a.ok(v, LogAction.Restore)
            a.synced()
            assertEquals(null, assertIs<VaultLogStatus.Verified>(a.logs.status(v)).state.deletedId)

            // An ownership offer and its acceptance.
            a.ok(v, LogAction.Add(b.userId, "writer"))
            accept(b, v)
            a.ok(v, LogAction.Offer(b.userId, 86_400_000L))
            b.synced()
            b.ok(v, LogAction.Accept)
            a.synced()
            assertEquals(b.userId, assertIs<VaultLogStatus.Verified>(a.logs.status(v)).state.owner)
        } }
    }
}
