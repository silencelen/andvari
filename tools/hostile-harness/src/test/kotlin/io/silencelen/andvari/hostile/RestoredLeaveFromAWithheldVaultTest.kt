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
import io.silencelen.andvari.core.model.wire.WireRoute
import kotlinx.serialization.json.jsonPrimitive
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull

/**
 * What the shared engine does today after an honest restore of the server, written down as it is and not as a rule of
 * the design: a member leaves a shared vault from a device that verified an entry the restore lost.
 *
 * Alice makes Bob a reader after the snapshot (seq 2), and Bob's device verifies it. The server is put back from the
 * snapshot: its log ends at seq 1. Bob's device signs in again (the restore ended its session) and syncs: the vault is
 * withheld there. Bob leaves: the leave is signed after the head his device verified. What the server answers, what the
 * engine answers, what is stored and what the device holds afterwards are pinned here.
 *
 * Over the real server in its test mode, a real restore of its database (`andvari admin restored`) and the devices of
 * the shared code (the command-line host).
 */
class RestoredLeaveFromAWithheldVaultTest {
    private val aliceMail = "alice@example.org"
    private val bobMail = "bob@example.org"

    private suspend fun World.signIn(h: Host, email: String) {
        var r = h.onboarding(origin).signIn(email, Steps.PASSWORD.toCharArray())
        if (r is SignIn.TrustGateFirst) {
            val gate = assertIs<FirstPin.NeedsTrustGate>(h.trust.beginTrustGate(origin, TrustGateWording.TYPED_ADDRESS))
            h.trust.confirmTrustGate(gate.confirm)
            r = h.onboarding(origin).signIn(email, Steps.PASSWORD.toCharArray())
        }
        assertIs<SignIn.SignedIn>(r, "$email signs in again: $r")
    }

    /** The log appends [tag] sent since [mark], each as its status and the server's error code. */
    private fun World.appends(tag: String, mark: Int): List<String> = proxy.since(mark)
        .filter { it.req.tag == tag && it.req.route == WireRoute.LOG_APPEND }
        .map { "${it.upstream?.status}:${it.upstream?.json?.get("error")?.jsonPrimitive?.content}" }

    private fun standing(s: AccountSession, v: String): String = when (val st = s.logs.status(v)) {
        is VaultLogStatus.Withheld -> "withheld:${st.state.headSeq}/${st.servedSeq}"
        is VaultLogStatus.Verified -> "verified:${st.state.headSeq}"
        is VaultLogStatus.Frozen -> "frozen:${st.seq}"
        is VaultLogStatus.Failed -> "failed:${st.verdict}"
        else -> st::class.simpleName ?: "?"
    }

    @Test fun aLeaveFromADeviceThatVerifiedALostEntryIsRefusedAndNothingIsStored() = world {
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
        b.synced()
        assertEquals(2L, assertIs<VaultLogStatus.Verified>(b.logs.status(v)).state.headSeq, "Bob's device verified the entry the restore loses")

        server.advance(60_000L)
        restoreFrom(snapshot) { env -> adminRestored(env).also { assertEquals(0, it.code, "${it.out} ${it.err}") } }

        runCatching { b.sync() }
        assertNull(bh.account(origin), "the restore ended Bob's session")
        signIn(bh, bobMail)
        val nb = account(bh)
        nb.synced()
        assertEquals("withheld:2/1", standing(nb, v), "the vault is withheld on Bob's device")

        // Bob leaves.
        val mark = proxy.mark()
        val left = nb.logs.append(v, LogAction.Leave)
        val sentAtLeave = appends("bob", mark)
        // The claim: the server refuses it with 409 log_head_moved.
        assertEquals(listOf("409:log_head_moved"), sentAtLeave, "the leave reaches the server, which refuses it")

        val held = nb.logs.heldChange(v)
        val mark2 = proxy.mark()
        nb.synced()
        nb.synced()
        val sentAtSyncs = appends("bob", mark2)
        val afterSyncs = standing(nb, v)
        val heldAfterSyncs = nb.logs.heldChange(v)
        // What the server holds: read by a fresh device of Alice's (the restored log, with Bob still in it).
        val a3 = account(passwordDevice("alice3", aliceMail))
        a3.synced()
        a3.synced()
        val onServer = assertIs<VaultLogStatus.Verified>(a3.logs.status(v), "Alice's fresh device: ${a3.logs.status(v)}").state

        assertEquals(
            listOf(
                "outcome" to "Pending",
                "held" to true,
                "syncs sent" to emptyList<String>(),
                "after syncs" to "withheld:2/1",
                "held after syncs" to true,
                "server head" to 1L,
                "bob a member on the server" to true,
            ).toString(),
            listOf(
                "outcome" to left::class.simpleName,
                "held" to (held != null),
                "syncs sent" to sentAtSyncs,
                "after syncs" to afterSyncs,
                "held after syncs" to (heldAfterSyncs != null),
                "server head" to onServer.headSeq,
                "bob a member on the server" to onServer.members.containsKey(b.userId),
            ).toString(),
        )
    }
}
