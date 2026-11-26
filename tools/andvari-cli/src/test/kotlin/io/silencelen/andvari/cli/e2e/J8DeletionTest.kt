package io.silencelen.andvari.cli.e2e

import io.silencelen.andvari.cli.Host
import io.silencelen.andvari.core.client.MemoryDeviceState
import io.silencelen.andvari.core.client.deletion.DeletionOutcome
import io.silencelen.andvari.core.client.log.LogAction
import io.silencelen.andvari.core.client.log.VaultLogStatus
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/** Journey 8: account deletion with its leaves (design §3.11). */
class J8DeletionTest {
    @Test fun aMemberDeletesTheAccountAndLeavesEverySharedVault() {
        TestServer().use { it.journey { val s = this
            Steps.registerThrough(s.device("operator"), s.origin, s.setupLink, "op@example.org")
            val ah = s.device("alice")
            Steps.registerThrough(ah, s.origin, Steps.enrolLink(s), "alice@example.org", trustGate = true)
            val bh = s.device("bob")
            Steps.registerThrough(bh, s.origin, Steps.enrolLink(s), "bob@example.org", trustGate = true)
            connect(ah, bh, s.origin)
            val a = ah.account(s.origin)!!
            val b = bh.account(s.origin)!!
            a.synced()
            val v = a.ok(null, LogAction.Create("Family"))
            a.ok(v, LogAction.Add(b.userId, "writer"))
            accept(b, v)

            var deleted = 0
            val del = b.deletion { deleted++ }
            val preview = assertNotNull(del.preview(), "the deletion preview")
            assertTrue(preview.toString().contains(v), "the preview names the shared vault: $preview")
            assertEquals(DeletionOutcome.EmailMismatch, del.delete("someone@example.org", Steps.PASSWORD.toCharArray(), null))
            val out = del.delete("bob@example.org", Steps.PASSWORD.toCharArray(), null)
            assertIs<DeletionOutcome.Deleted>(out, "deletion: $out")
            assertEquals(1, deleted)

            // The leave was signed and verifies for the owner; the account is gone.
            a.synced()
            val st = assertIs<VaultLogStatus.Verified>(a.logs.status(v))
            assertTrue(b.userId !in st.state.members, "the deleted account left the vault")
            val keys = bh.client(s.origin).call(io.silencelen.andvari.core.model.wire.WireRoute.ACCOUNT_KEYS, decode = { it })
            assertIs<io.silencelen.andvari.core.client.net.WireResult.Refused>(keys, "the deleted account's session is gone: $keys")
            assertTrue(s.admin("accounts").lines().none { it.contains("bob@example.org") && it.contains("active") })
        } }
    }

    /**
     * The leaves are placed from the log engine's OWN verified state (design §3.11, FS-R7), not from a record the host
     * reads: when one of Bob's trust records for the vault cannot be read, the served head counts as unverified, and
     * with his clock two days behind the server's that head is too far ahead to sign after. Nothing is signed or sent.
     * Readable again, the head is his verified one and the deletion goes through.
     */
    @Test fun aLeaveIsPlacedFromTheLogEnginesOwnStateAndAnUnreadableTrustRecordMakesTheHeadUnverified() {
        TestServer().use { it.journey { val s = this
            Steps.registerThrough(s.device("operator"), s.origin, s.setupLink, "op@example.org")
            val ah = s.device("alice")
            Steps.registerThrough(ah, s.origin, Steps.enrolLink(s), "alice@example.org", trustGate = true)
            var lag = 0L
            val bh = Host(MemoryDeviceState(), MemoryDeviceState(), { s.now() - lag }, http = s.httpFor(), deviceName = "bob")
            Steps.registerThrough(bh, s.origin, Steps.enrolLink(s), "bob@example.org", trustGate = true)
            connect(ah, bh, s.origin)
            val a = ah.account(s.origin)!!
            val b = bh.account(s.origin)!!
            a.synced()
            val v = a.ok(null, LogAction.Create("Family"))
            a.ok(v, LogAction.Add(b.userId, "writer"))
            accept(b, v)
            b.synced()
            assertIs<VaultLogStatus.Verified>(b.logs.status(v))

            lag = 2L * 24 * 60 * 60 * 1000
            val hashesKey = "ovh.log|${b.userId}|$v|hashes"
            val hashes = assertNotNull(bh.state.get(hashesKey), "Bob's device keeps the hashes it verified")
            bh.state.set(hashesKey, "not a hashes record")
            var deleted = 0
            val del = b.deletion { deleted++ }
            assertEquals(DeletionOutcome.FutureHead, del.delete("bob@example.org", Steps.PASSWORD.toCharArray(), null))
            assertEquals(0, deleted)
            assertTrue(s.admin("accounts").lines().any { it.contains("bob@example.org") && it.contains("active") }, "nothing was sent")

            bh.state.set(hashesKey, hashes)
            assertIs<DeletionOutcome.Deleted>(del.delete("bob@example.org", Steps.PASSWORD.toCharArray(), null))
            assertEquals(1, deleted)
            a.synced()
            assertTrue(b.userId !in assertIs<VaultLogStatus.Verified>(a.logs.status(v)).state.members, "the leave verifies for the owner")
        } }
    }
}
