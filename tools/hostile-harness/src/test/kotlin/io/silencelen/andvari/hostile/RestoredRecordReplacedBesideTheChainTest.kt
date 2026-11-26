package io.silencelen.andvari.hostile

import io.silencelen.andvari.cli.AccountSession
import io.silencelen.andvari.cli.Host
import io.silencelen.andvari.cli.e2e.Steps
import io.silencelen.andvari.cli.e2e.doc
import io.silencelen.andvari.cli.e2e.ok
import io.silencelen.andvari.cli.e2e.synced
import io.silencelen.andvari.core.client.log.LogAction
import io.silencelen.andvari.core.client.log.VaultLogStatus
import io.silencelen.andvari.core.client.onboard.SignIn
import io.silencelen.andvari.core.client.pin.FirstPin
import io.silencelen.andvari.core.client.pin.TrustGateWording
import io.silencelen.andvari.core.client.state.VaultRecord
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * What the shared engine does today after an honest restore of the server, written down as it is and not as a rule of
 * the design: the account's record of a shared vault, put back by an older device, is replaced by the head of a fresh
 * device that wrote on the restored chain past the record's place.
 *
 * Alice's first device verifies seq 2 after the snapshot and, ten minutes later, writes that head into her account's
 * records. The server is put back from the snapshot (its log ends at seq 1, its account records are the backup's). A
 * fresh device of Alice's signs in before any older device syncs: it is verified on the restored log and makes two
 * entries there, so its head (seq 3) is above the record's place. Her first device then signs in again and makes a
 * vault, which writes the higher record back. At the fresh device's next opening, ten minutes on, it reads that record.
 *
 * Over the real server in its test mode, a real restore of its database (`andvari admin restored`) and the devices of
 * the shared code (the command-line host).
 */
class RestoredRecordReplacedBesideTheChainTest {
    private val aliceMail = "alice@example.org"

    private suspend fun World.signIn(h: Host, email: String) {
        var r = h.onboarding(origin).signIn(email, Steps.PASSWORD.toCharArray())
        if (r is SignIn.TrustGateFirst) {
            val gate = assertIs<FirstPin.NeedsTrustGate>(h.trust.beginTrustGate(origin, TrustGateWording.TYPED_ADDRESS))
            h.trust.confirmTrustGate(gate.confirm)
            r = h.onboarding(origin).signIn(email, Steps.PASSWORD.toCharArray())
        }
        assertIs<SignIn.SignedIn>(r, "$email signs in again: $r")
    }

    private suspend fun World.fresh(tag: String): AccountSession {
        val s = account(passwordDevice(tag, aliceMail))
        s.sync()
        s.sync()
        return s
    }

    /** The account's record of [v] as the server holds it now, read (and nothing written) by a new device [tag]. */
    private suspend fun World.serverRecord(tag: String, v: String): VaultRecord? {
        val s = account(passwordDevice(tag, aliceMail))
        s.readAccountStateOnce()
        return s.store.local().vaults[v]
    }

    private fun headOf(s: AccountSession, v: String): String = when (val st = s.logs.status(v)) {
        is VaultLogStatus.Verified -> "verified:${st.state.headSeq}"
        is VaultLogStatus.Withheld -> "withheld:${st.state.headSeq}"
        is VaultLogStatus.Frozen -> "frozen:${st.seq}"
        is VaultLogStatus.Failed -> "failed:${st.verdict}"
        else -> st::class.simpleName ?: "?"
    }

    @Test fun aFreshDeviceWhoseHeadPassedTheRecordsPlaceStaysWritableAndReplacesTheRecord() = world {
        operator()
        val ah = member("alice")
        val bh = member("bob")
        val v = sharedVault(ah, bh, "Shared")
        val a = account(ah)
        val b = account(bh)
        assertNotNull(a.putItem(v, doc("shared item")).first)
        a.synced()
        b.synced()
        val snapshot = takeSnapshot()
        a.ok(v, LogAction.Role(b.userId, "reader"))
        a.synced()
        server.advance(10 * 60_000L)
        a.synced()
        val lost = assertNotNull(a.store.local().vaults[v], "Alice's first device recorded the head it verified")
        assertEquals(2L, lost.seq)

        server.advance(60_000L)
        restoreFrom(snapshot) { env -> adminRestored(env).also { assertEquals(0, it.code, "${it.out} ${it.err}") } }

        // A fresh device before any older device syncs: verified on the restored log, writable; its head passes seq 2.
        val a3 = fresh("alice3")
        assertEquals("verified:1", headOf(a3, v), "the fresh device on the restored log")
        assertTrue(a3.writeAllowed(v))
        a3.ok(v, LogAction.Role(b.userId, "writer"))
        a3.ok(v, LogAction.Role(b.userId, "reader"))
        val head = assertIs<VaultLogStatus.Verified>(a3.logs.status(v)).state
        assertEquals(3L, head.headSeq)
        val freshHead = VaultRecord(v, lost.genesisHash, head.headSeq, head.headHash)

        // Alice's first device signs in again (the restore ended its session) and makes a vault: the higher record is back.
        runCatching { a.sync() }
        assertNull(ah.account(origin), "the restore ended the first device's session")
        signIn(ah, aliceMail)
        val na = account(ah)
        na.sync()
        na.sync()
        na.ok(null, LogAction.Create("Another"))
        assertEquals(lost, serverRecord("alice8", v), "the first device wrote the higher record back")

        // The fresh device's next opening, ten minutes on: it reads that record.
        server.advance(11 * 60_000L)
        val r3 = account(restarted(a3.host))
        r3.sync()
        r3.sync()
        assertEquals(
            listOf("standing=verified:3", "writable=true", "own copy=$freshHead"),
            listOf("standing=${headOf(r3, v)}", "writable=${r3.writeAllowed(v)}", "own copy=${r3.store.local().vaults[v]}"),
            "the fresh device after it read the higher record",
        )
        assertEquals(freshHead, serverRecord("alice9", v), "the account's record now names the fresh device's head")

        // A new device of the account: verified on the restored chain, and it writes.
        val a5 = fresh("alice5")
        assertEquals("verified:3", headOf(a5, v), "a new device")
        assertTrue(a5.writeAllowed(v), "a new device may write")
        assertNull(a5.putItem(v, doc("from a new device")).second, "an item write by the new device is stored")

        // The first device, at its next opening: its own copy follows the new record, and the vault opens read-only,
        // frozen at seq 2, the place where the restored chain parts from the entry this device had verified.
        val r1 = account(restarted(ah))
        r1.sync()
        r1.sync()
        assertEquals(
            listOf("standing=frozen:2", "writable=false", "own copy=$freshHead"),
            listOf("standing=${headOf(r1, v)}", "writable=${r1.writeAllowed(v)}", "own copy=${r1.store.local().vaults[v]}"),
            "the first device after the record was replaced",
        )
    }
}
