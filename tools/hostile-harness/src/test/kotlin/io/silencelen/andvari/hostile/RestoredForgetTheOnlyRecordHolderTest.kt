package io.silencelen.andvari.hostile

import io.silencelen.andvari.cli.AccountSession
import io.silencelen.andvari.cli.SavedSessions
import io.silencelen.andvari.cli.e2e.Steps
import io.silencelen.andvari.cli.e2e.doc
import io.silencelen.andvari.cli.e2e.ok
import io.silencelen.andvari.cli.e2e.synced
import io.silencelen.andvari.core.client.log.LogAction
import io.silencelen.andvari.core.client.log.VaultLogStatus
import io.silencelen.andvari.core.client.onboard.SignIn
import io.silencelen.andvari.core.client.pin.FirstPin
import io.silencelen.andvari.core.client.pin.TrustGateWording
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * What the shared engine does today after an honest restore of the server, written down as it is and not as a rule of
 * the design: the only device that holds the account's higher record of a shared vault forgets the server before it
 * writes the account again.
 *
 * Alice has one device. It verifies seq 2 after the snapshot and, ten minutes later, writes that head into her account's
 * records. The server is put back from the snapshot: its log ends at seq 1 and its account records are the backup's.
 * Before her device writes the account again, she has it forget the server, and signs in again. What the account's
 * record is then, and what her device and a new one make of the vault, is pinned here.
 *
 * Over the real server in its test mode, a real restore of its database (`andvari admin restored`) and the devices of
 * the shared code (the command-line host).
 */
class RestoredForgetTheOnlyRecordHolderTest {
    private val aliceMail = "alice@example.org"

    private fun standing(s: AccountSession, v: String): String = when (val st = s.logs.status(v)) {
        is VaultLogStatus.Withheld -> "withheld:${st.state.headSeq}"
        is VaultLogStatus.Verified -> "verified:${st.state.headSeq}"
        is VaultLogStatus.Frozen -> "frozen:${st.seq}"
        is VaultLogStatus.Failed -> "failed:${st.verdict}"
        else -> st::class.simpleName ?: "?"
    }

    @Test fun forgettingTheOnlyHolderOfTheHigherRecordBeforeAnAccountWriteLeavesNoLowerBound() = world {
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
        val lost = assertNotNull(a.store.local().vaults[v], "Alice's only device recorded the head it verified")
        assertEquals(2L, lost.seq)

        server.advance(60_000L)
        restoreFrom(snapshot) { env -> adminRestored(env).also { assertEquals(0, it.code, "${it.out} ${it.err}") } }

        // Before any account write: "Forget this server", then the typed address through the Trust Gate and the password.
        ah.forgetServer(origin, SavedSessions(ah.secure), aliceMail)
        val gate = assertIs<FirstPin.NeedsTrustGate>(ah.trust.beginTrustGate(origin, TrustGateWording.TYPED_ADDRESS))
        ah.trust.confirmTrustGate(gate.confirm)
        assertIs<SignIn.SignedIn>(ah.onboarding(origin).signIn(aliceMail, Steps.PASSWORD.toCharArray()))
        val f = account(ah)
        f.sync()
        f.sync()

        // The claim: the account keeps no record at or above the lost entry.
        val reader = account(passwordDevice("alice8", aliceMail))
        reader.readAccountStateOnce()
        val record = reader.store.local().vaults[v]
        assertTrue(record == null || record.seq < lost.seq, "the account's record is below the lost entry: $record")

        val forgot = listOf(standing(f, v), "writable=${f.writeAllowed(v)}", "save=${f.putItem(v, doc("after forgetting")).second}")
        f.synced()
        val a5 = account(passwordDevice("alice5", aliceMail))
        a5.sync()
        a5.sync()
        val fresh = listOf(standing(a5, v), "writable=${a5.writeAllowed(v)}", "items=${itemNames(a5.items(v)).sorted()}")

        assertEquals(
            listOf(
                "record seq" to 1L,
                "forgot" to listOf("verified:1", "writable=true", "save=null"),
                "fresh" to listOf("verified:1", "writable=true", "items=[after forgetting, shared item]"),
            ).toString(),
            listOf("record seq" to record?.seq, "forgot" to forgot, "fresh" to fresh).toString(),
        )
    }
}
