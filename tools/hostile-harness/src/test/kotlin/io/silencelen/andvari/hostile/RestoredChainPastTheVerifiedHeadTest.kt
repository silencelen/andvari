package io.silencelen.andvari.hostile

import io.silencelen.andvari.cli.AccountSession
import io.silencelen.andvari.cli.Host
import io.silencelen.andvari.cli.SyncOutcome
import io.silencelen.andvari.cli.e2e.Steps
import io.silencelen.andvari.cli.e2e.connect
import io.silencelen.andvari.cli.e2e.doc
import io.silencelen.andvari.cli.e2e.ok
import io.silencelen.andvari.cli.e2e.synced
import io.silencelen.andvari.core.client.log.Adoption
import io.silencelen.andvari.core.client.log.AdoptionRefusal
import io.silencelen.andvari.core.client.log.AppendOutcome
import io.silencelen.andvari.core.client.log.KeySource
import io.silencelen.andvari.core.client.log.LogAction
import io.silencelen.andvari.core.client.log.VaultLogStatus
import io.silencelen.andvari.core.client.log.VerifiedVaultState
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
 * A device that verified entries of a shared vault's log which an honest restore of the server lost, and that syncs only
 * after the restored chain has grown past the head it verified (design §3.6 (e), §3.9; decided on 23 November 2026: every
 * device of the account opens such a vault read-only, and it stays closed to changes for good).
 *
 * The first entry the server serves after the device's head does not chain onto it, so the device reads the log again
 * from its beginning against every hash it holds. The restored chain's own entry at the first place where it differs
 * from what the device verified is validly signed, so the vault is frozen there (a fork), its state stands at the entry
 * before that place, and the key is taken read-only. A chain with another beginning under the vault's id gives no key.
 *
 * Over the real server in its test mode, a real restore of its database (`andvari admin restored`) and the devices of
 * the shared code (the command-line host, whose item cache lives in memory, one per session).
 */
class RestoredChainPastTheVerifiedHeadTest {
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

    /** [h]'s next contact after the restore: the session it held has ended, so it signs in again. */
    private suspend fun World.again(h: Host, email: String): AccountSession {
        assertIs<SyncOutcome.Refused>(account(h).sync(), "the session held before the restore has ended")
        assertNull(h.account(origin), "signed out")
        signIn(h, email)
        return account(h)
    }

    /** The account's record of [v] as the server holds it now, read (and nothing written) by a new device [tag]. */
    private suspend fun World.serverRecord(tag: String, email: String, v: String): VaultRecord? {
        val s = account(passwordDevice(tag, email))
        s.readAccountStateOnce()
        return s.store.local().vaults[v]
    }

    private fun World.restored(snapshot: Snapshot) {
        server.advance(60_000L)
        restoreFrom(snapshot) { env -> adminRestored(env).also { assertEquals(0, it.code, "${it.out} ${it.err}") } }
    }

    /** What [s] shows of [v]: its standing, whether a key is held, its items read, the server's row, the vault list, writes. */
    private fun facts(s: AccountSession, v: String): List<String> = listOf(
        when (val st = s.logs.status(v)) {
            is VaultLogStatus.Failed -> "failed:${st.verdict}"
            is VaultLogStatus.Frozen -> "frozen:${st.seq} head=${st.state.headSeq}"
            is VaultLogStatus.Verified -> "verified:${st.state.headSeq}"
            else -> st::class.simpleName ?: "?"
        },
        "key=${s.logs.keyFor(v) != null}",
        "items=${itemNames(s.items(v)).sorted()}",
        "row=${v in s.vaultIds()}",
        "listed=${s.items.vaults().singleOrNull { it.vaultId == v }?.standing}",
        "writable=${s.writeAllowed(v)}",
    )

    /** What alice1 showed: after the sync that met the grown chain, a second sync, a restart, and a sync after it. */
    private class Seen(
        val synced: List<String>, val refusal: String?, val logRefusal: AppendOutcome, val again: List<String>,
        val restarted: List<String>, val restartedSynced: List<String>, val reopened: Adoption, val adoption: Adoption,
        val state: VaultLogStatus, val before: VerifiedVaultState, val recordBefore: VaultRecord?, val recordAfter: VaultRecord?,
        val written: List<String>,
    )

    /** The course, up to alice1's sync after a restart. */
    private suspend fun World.course(): Seen {
        operator()
        val ah = member("alice")
        val bh = member("bob")
        val v = sharedVault(ah, bh, "Shared")
        val a = account(ah)
        val b = account(bh)
        assertNotNull(a.putItem(v, doc("shared item")).first)
        a.synced()
        b.synced()
        val dh = pinnedDevice("alice1")
        assertIs<SignIn.SignedIn>(dh.onboarding(origin).signIn(aliceMail, Steps.PASSWORD.toCharArray()))
        account(dh).synced()
        val before = assertIs<VaultLogStatus.Verified>(account(dh).logs.status(v), "alice1 before the entry the restore loses").state
        assertEquals(1L, before.headSeq)
        val snapshot = takeSnapshot()
        a.ok(v, LogAction.Role(b.userId, "reader"))
        account(dh).synced()
        val verified = assertIs<VaultLogStatus.Verified>(account(dh).logs.status(v), "alice1 verified the entry the restore loses").state
        assertEquals(2L, verified.headSeq)

        restored(snapshot)

        // A fresh device of Alice's, before alice1 syncs: verified on the restored log; it makes seq 2 and 3.
        val a3 = account(passwordDevice("alice3", aliceMail))
        a3.sync()
        a3.sync()
        assertEquals(1L, assertIs<VaultLogStatus.Verified>(a3.logs.status(v), "the fresh device: ${a3.logs.status(v)}").state.headSeq)
        assertTrue(a3.writeAllowed(v), "the fresh device may write")
        a3.ok(v, LogAction.Role(b.userId, "reader"))
        a3.ok(v, LogAction.Role(b.userId, "writer"))
        assertEquals(3L, assertIs<VaultLogStatus.Verified>(a3.logs.status(v)).state.headSeq, "the restored chain ends above the head alice1 verified")
        // The restored server is used for a while: its sync counter passes the one alice1 last saw.
        val personal3 = assertNotNull(a3.personalVaultId)
        for (i in 1..3) assertNull(a3.putItem(personal3, doc("after $i")).second)
        a3.synced()
        val recordBefore = serverRecord("alice7", aliceMail, v)

        // alice1: the restore ended its session (`andvari admin restored`), so it signs in again and syncs.
        val s = again(dh, aliceMail)
        val mark = proxy.mark()
        s.synced()
        val state = s.logs.status(v)
        val synced = facts(s, v)
        val refusal = s.putItem(v, doc("on a frozen log")).second
        val logRefusal = s.logs.append(v, LogAction.Role(b.userId, "reader"))
        s.synced()
        val again = facts(s, v)
        val written = proxy.requests(tag = tag(dh), since = mark).filter { it.method != "GET" }.map { "${it.method} ${it.path}" }

        // A restart: new engine objects over the same device state. Before its next sync: the cache opened, nothing sent.
        val r = account(restarted(dh))
        r.items.hydrate()
        val restarted = facts(r, v)
        val reopened = r.logs.reopenAdopted(v)
        r.synced()
        val restartedSynced = facts(r, v)
        val adoption = r.logs.adoption(v)
        return Seen(synced, refusal, logRefusal, again, restarted, restartedSynced, reopened, adoption, state, before,
            recordBefore, serverRecord("alice8", aliceMail, v), written)
    }

    /**
     * The command-line host: alice1 opens the vault read-only, frozen at the lost entry's place, in the session that
     * synced and after a restart and a sync. Its state stands at the entry before that place; nothing is written.
     */
    @Test fun aDeviceThatVerifiedALostEntryAndSyncsAfterTheRestoredChainGrewPastItsHead() = world {
        val seen = course()
        val v = seen.reopened.vaultId
        val frozen = assertIs<VaultLogStatus.Frozen>(seen.state, "the vault's standing after that sync")
        assertEquals(seen.before, frozen.state, "the state stands at the entry before the place where the chains part")
        // In the session that synced: frozen, its key held, its items read, listed read-only, not writable.
        val read = listOf("frozen:2 head=1", "key=true", "items=[shared item]", "row=true", "listed=FROZEN", "writable=false")
        assertEquals(read, seen.synced, "in the session that synced")
        assertEquals(READ_ONLY, seen.refusal, "an item write is refused: the vault is read-only")
        assertEquals(AppendOutcome.VaultReadOnly, seen.logRefusal, "a change of the log is refused")
        assertEquals(read, seen.again, "after a second sync")
        assertEquals(emptyList(), seen.written, "nothing that writes was sent from that session")
        // After a restart, before a sync: the log engine still calls it frozen; the empty cache holds no row of it.
        assertEquals(listOf("frozen:2 head=1", "key=false", "items=[]", "row=false", "listed=null", "writable=false"), seen.restarted, "after a restart, before a sync")
        assertEquals(Adoption.Refused(v, AdoptionRefusal.NO_KEY), seen.reopened, "the reopen finds no row to take the key from")
        assertEquals(read, seen.restartedSynced, "after a restart and a sync")
        assertEquals(Adoption.Adopted(v, KeySource.OWNER_WRAP), seen.adoption, "the key is taken again, read-only")
        assertEquals(seen.recordBefore, seen.recordAfter, "the account's record of the vault is as it was")
    }

    /**
     * A member's device frozen above the account's record. Bob owns "Shared"; Alice's device accepts (her account records
     * seq 1) and verifies seq 2 and, after the snapshot, seq 3, which the restore loses; the batching keeps the record at
     * seq 1. A fresh device of Bob's then makes seq 3, 4 and 5 on the restored log. Eleven minutes on, Alice's device signs in again and syncs:
     * frozen at seq 3, its key held (the record agrees with the chain to seq 2), read-only, and the account's record is
     * not raised to the entry before the fork. A fresh device of Alice's verifies the restored chain past the record and
     * may write: no record of the account stands at or above the place where the chains part.
     */
    @Test fun aMembersDeviceFrozenAboveTheAccountsRecordLeavesTheRecordAsItWas() = world {
        operator()
        val ah = member("alice")
        val bh = member("bob")
        val v = sharedVault(bh, ah, "Shared")
        val a = account(ah)
        val b = account(bh)
        assertNotNull(b.putItem(v, doc("shared item")).first)
        b.synced()
        a.synced()
        val record = assertNotNull(a.store.local().vaults[v], "Alice's account records the vault at her acceptance")
        assertEquals(1L, record.seq)
        b.ok(v, LogAction.Role(a.userId, "reader"))
        a.synced()
        val snapshot = takeSnapshot()
        b.ok(v, LogAction.Role(a.userId, "writer"))
        a.synced()
        assertEquals(3L, assertIs<VaultLogStatus.Verified>(a.logs.status(v), "Alice's device verified the entry the restore loses").state.headSeq)
        assertEquals(record, a.store.local().vaults[v], "the batching kept the record at seq 1")

        restored(snapshot)
        // A fresh device of Bob's (his first one verified the lost entry too): verified on the restored log; seq 3 to 5.
        val nb = account(passwordDevice("bob3", bobMail))
        nb.sync()
        nb.sync()
        nb.ok(v, LogAction.Role(a.userId, "writer"))
        nb.ok(v, LogAction.Role(a.userId, "reader"))
        nb.ok(v, LogAction.Role(a.userId, "writer"))
        nb.synced()

        server.advance(11 * 60_000L)
        val na = again(ah, aliceMail)
        val mark = proxy.mark()
        na.synced()
        val read = listOf("frozen:3 head=2", "key=true", "items=[shared item]", "row=true", "listed=FROZEN", "writable=false")
        assertEquals(read, facts(na, v), "in the session that synced")
        assertEquals(READ_ONLY, na.putItem(v, doc("on a frozen log")).second, "an item write is refused")
        na.synced()
        assertEquals(read, facts(na, v), "after a second sync")
        assertEquals(emptyList(), proxy.requests(tag = tag(ah), since = mark).filter { it.method != "GET" }.map { "${it.method} ${it.path}" },
            "nothing that writes was sent from that session")
        assertEquals(record, serverRecord("alice8", aliceMail, v), "the account's record is as it was")

        // A fresh device of Alice's: verified on the restored chain past the record, and writable.
        val a9 = account(passwordDevice("alice9", aliceMail))
        a9.sync()
        a9.sync()
        assertEquals("verified:5", facts(a9, v).first(), "a fresh device")
        assertTrue(a9.writeAllowed(v), "a fresh device may write")
        assertNull(a9.putItem(v, doc("from a fresh device")).second, "its item write is stored")
    }

    /**
     * Another vault served under the vault's id, past the head the device verified. "Shared" is made after the snapshot,
     * Bob is added (seq 1) and never syncs it; the restore loses the vault. Bob then makes a chain of his own under the
     * same id, puts an item into it, adds Alice and makes two more entries (its head is seq 3). Alice's device, which
     * verified seq 1 of her chain, freezes at the beginning: no key, nothing of Bob's chain read, not writable, also after a
     * restart.
     */
    @Test fun aChainWithAnotherBeginningServedPastTheVerifiedHeadGivesNoKey() = world {
        operator()
        val ah = member("alice")
        val bh = member("bob")
        connect(ah, bh, origin)
        val a = account(ah)
        val b = account(bh)
        a.synced()
        b.synced()
        val snapshot = takeSnapshot()
        val v = a.ok(null, LogAction.Create("Shared"))
        a.ok(v, LogAction.Add(b.userId, "writer"))
        assertNotNull(a.putItem(v, doc("shared item")).first)
        a.synced()
        assertEquals(1L, assertIs<VaultLogStatus.Verified>(a.logs.status(v)).state.headSeq)

        restored(snapshot)
        val nb = again(bh, bobMail)
        nb.synced()
        assertEquals(v, nb.ok(null, LogAction.Create("Shared", vaultId = v)), "Bob makes a chain of his own under the vault's id")
        assertNotNull(nb.putItem(v, doc("other chain item")).first)
        nb.synced()
        nb.ok(v, LogAction.Add(a.userId, "writer"))
        nb.ok(v, LogAction.Role(a.userId, "reader"))
        nb.ok(v, LogAction.Role(a.userId, "writer"))
        nb.synced()

        val na = again(ah, aliceMail)
        val mark = proxy.mark()
        na.synced()
        val none = listOf("frozen:0 head=1", "key=false", "items=[]", "row=true", "listed=null", "writable=false")
        assertEquals(none, facts(na, v), "in the session that synced")
        val adoption = na.logs.adoption(v)
        assertEquals(Adoption.Refused(v, AdoptionRefusal.GRANT_REFUSED), adoption, "no key is taken: the grant row is Bob's chain's")
        assertEquals("vault_not_open", na.putItem(v, doc("into the other chain")).second, "an item write is refused")
        assertEquals(AppendOutcome.VaultReadOnly, na.logs.append(v, LogAction.Role(b.userId, "reader")), "a change of the log is refused")
        na.synced()
        assertEquals(none, facts(na, v), "after a second sync")
        assertEquals(emptyList(), proxy.requests(tag = tag(ah), since = mark).filter { it.method != "GET" }.map { "${it.method} ${it.path}" },
            "nothing that writes was sent from that session")

        val r = account(restarted(ah))
        r.items.hydrate()
        assertEquals(listOf("frozen:0 head=1", "key=false", "items=[]", "row=false", "listed=null", "writable=false"), facts(r, v), "after a restart, before a sync")
        assertEquals(Adoption.Refused(v, AdoptionRefusal.NO_KEY), r.logs.reopenAdopted(v), "the reopen takes no key")
        r.synced()
        assertEquals(none, facts(r, v), "after a restart and a sync")
        assertEquals(adoption, r.logs.adoption(v), "the key is not taken after the restart either")
    }
}
