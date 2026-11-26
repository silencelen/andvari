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
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull

/**
 * What the shared engine does today after an honest restore of the server, written down as it is and not as a rule of
 * the design: a leave that the restore lost.
 *
 * Bob leaves Alice's vault "Left" after the snapshot, and ten minutes later his device writes the leave (a decline of
 * his add) into his account's records. The server is put back from the snapshot: its log ends before the leave, and its
 * account records hold Bob's earlier answer (accept). A fresh device of Bob's signs in before any older device of his
 * syncs; later his first device signs in again and makes a vault, which writes his records back.
 *
 * Over the real server in its test mode, a real restore of its database (`andvari admin restored`) and the devices of
 * the shared code (the command-line host).
 */
class RestoredLostLeaveTest {
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

    private suspend fun World.fresh(tag: String, email: String): AccountSession {
        val s = account(passwordDevice(tag, email))
        s.sync()
        s.sync()
        return s
    }

    /** What [s] shows of [x]: its standing and head, its adoption, the account's answer it holds, writes, and an item write. */
    private suspend fun facts(s: AccountSession, x: String, item: String): List<String> {
        val st = s.logs.status(x)
        val head = (st as? VaultLogStatus.Verified)?.state?.headSeq
        return listOf(
            "log=${st::class.simpleName}:$head",
            "adoption=${s.logs.adoption(x)::class.simpleName}",
            "answer=${s.store.local().accepted[x]?.decision}",
            "writable=${s.writeAllowed(x)}",
            "save=${s.putItem(x, doc(item)).second}",
        )
    }

    @Test fun theLeaversFreshDeviceBeforeTheAccountIsWrittenBackOpensTheVaultWritable() = world {
        operator()
        val ah = member("alice")
        val bh = member("bob")
        val x = sharedVault(ah, bh, "Left")
        val a = account(ah)
        val b = account(bh)
        assertNotNull(a.putItem(x, doc("x item")).first)
        a.synced()
        b.synced()
        val snapshot = takeSnapshot()
        b.ok(x, LogAction.Leave)
        b.synced()
        server.advance(11 * 60_000L)
        b.synced()
        assertEquals("decline", b.store.local().accepted[x]?.decision, "the leave is in the account's records")

        server.advance(60_000L)
        restoreFrom(snapshot) { env -> adminRestored(env).also { assertEquals(0, it.code, "${it.out} ${it.err}") } }

        // Bob's fresh device, before any older device of his syncs.
        val b3 = fresh("bob3", bobMail)
        assertEquals(listOf("log=Verified:1", "adoption=Adopted", "answer=accept", "writable=true", "save=null"), facts(b3, x, "from bob3"),
            "the leaver's fresh device opens the vault verified and writable, and an item write is taken")
        b3.synced()
        // What reached the server: read by a fresh device of Alice's, which never saw the leave.
        val a4 = fresh("alice4", aliceMail)
        val readByAlice = itemNames(a4.items(x)).sorted()
        val bobMember = (a4.logs.status(x) as? VaultLogStatus.Verified)?.state?.members?.containsKey(b.userId)

        // Bob's first device signs in again and makes a vault: his records, with the leave, are back on the server.
        runCatching { b.sync() }
        assertNull(bh.account(origin), "the restore ended the first device's session")
        signIn(bh, bobMail)
        val nb = account(bh)
        nb.sync()
        nb.sync()
        nb.ok(null, LogAction.Create("Bob's own"))
        // A fresh device of Bob's after that, and the first fresh one at its next opening: the record of the leave's place
        // is above the restored log (withheld), the answer is the decline, the key is not taken, nothing is written.
        val b5 = fresh("bob5", bobMail)
        val later = facts(b5, x, "from bob5")
        val r3 = account(restarted(b3.host))
        r3.synced()
        val reopened = facts(r3, x, "from bob3 restarted")

        assertEquals(
            listOf(
                "readByAlice" to listOf("from bob3", "x item"),
                "bobMember" to true,
                "later" to listOf("log=Withheld:null", "adoption=ConnectFirst", "answer=decline", "writable=false", "save=vault_not_open"),
                "reopened" to listOf("log=Withheld:null", "adoption=ConnectFirst", "answer=decline", "writable=false", "save=vault_not_open"),
            ).toString(),
            listOf("readByAlice" to readByAlice, "bobMember" to bobMember, "later" to later, "reopened" to reopened).toString(),
        )
    }
}
