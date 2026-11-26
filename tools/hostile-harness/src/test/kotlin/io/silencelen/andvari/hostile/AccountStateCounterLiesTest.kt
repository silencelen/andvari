package io.silencelen.andvari.hostile

import io.silencelen.andvari.cli.e2e.accept
import io.silencelen.andvari.cli.e2e.connect
import io.silencelen.andvari.cli.e2e.doc
import io.silencelen.andvari.cli.e2e.ok
import io.silencelen.andvari.cli.e2e.synced
import io.silencelen.andvari.core.client.log.LogAction
import io.silencelen.andvari.core.model.wire.WireRoute
import io.silencelen.andvari.hostile.proxy.editAnswer
import io.silencelen.andvari.hostile.proxy.set
import kotlinx.serialization.json.JsonPrimitive
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The account state's counter on every sync answer (spec 03 §4 `accountStateSeq`), told by a server that lies about it in
 * each direction, against the real server. A password-only second device of Bob's waits for his answer to Alice's vault:
 * the honest counter standing still costs it no read of the account state; a counter far above or below the one it
 * last saw is read, never skipped; one held still over a write of his first device only withholds that answer (as
 * serving the older state would), and the device adopts once the counter moves. Nothing a lie says is ever adopted: the
 * state read is still merged, never taken whole.
 *
 * The sync tells the vault-log engine the counter (`SessionVaultKeys.served` calls `VaultLogEngine.accountStateServed`).
 */
class AccountStateCounterLiesTest {
    @Test fun aCounterThatLiesInEitherDirectionCostsReadsOrWithholdsAnAnswerAndNeverForgesOne() = world {
        operator()
        val ah = member("alice")
        val bh = member("bob")
        connect(ah, bh, origin)
        val a = account(ah)
        val b = account(bh)
        a.synced()
        val v = a.ok(null, LogAction.Create("Family"))
        assertEquals(null, a.putItem(v, doc("for bob")).second)
        a.ok(v, LogAction.Add(b.userId, "writer"))

        val dh = passwordDevice("bob2", "bob@example.org")
        val d = account(dh)
        d.synced()
        assertNull(d.vaultName(v), "no answer anywhere yet")
        fun counter(): Long = assertNotNull((proxy.last(WireRoute.SYNC, "bob2")?.upstream?.json?.get("accountStateSeq") as? JsonPrimitive)?.content?.toLong(), "the server serves the counter")
        fun readsSince(mark: Int) = sent(dh, WireRoute.ACCOUNT_STATE_GET, mark).size

        // 1. Honest, standing still: the invitation still waits, and nothing is read.
        var mark = proxy.mark()
        repeat(3) { d.synced() }
        assertEquals(0, readsSince(mark), "the counter stands still: no read")

        // 2. Far above and below the one the device last saw: read at each round, and nothing changes.
        val seen = counter()
        for (lie in listOf(seen + 1_000_000, seen - 1, 0L)) {
            if (lie == seen) continue
            val rule = proxy.on(WireRoute.SYNC, "bob2", handler = editAnswer { it.set("accountStateSeq", lie) })
            mark = proxy.mark()
            d.synced()
            rule.remove()
            assertEquals(1, readsSince(mark), "a counter of $lie (the device saw $seen): read, never skipped")
            assertNull(d.vaultName(v), "a lie adopts nothing")
        }

        // 3. Bob answers on his first device; the server holds the counter where the second device last saw it.
        accept(b, v, "Family")
        val still = proxy.on(WireRoute.SYNC, "bob2", handler = editAnswer { it.set("accountStateSeq", seen) })
        mark = proxy.mark()
        repeat(2) { d.synced() }
        assertEquals(0, readsSince(mark), "held still: not read")
        assertNull(d.vaultName(v), "the answer is withheld while the counter is held still (the stated limit)")
        still.remove()

        // 4. The counter moves: read once, and the vault is Bob's on this device too.
        mark = proxy.mark()
        d.synced()
        assertEquals(1, readsSince(mark))
        assertEquals("Family", d.vaultName(v))
        assertTrue(d.items.items().any { it.vaultId == v && it.doc.name == "for bob" })
    }
}
