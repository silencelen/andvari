package io.silencelen.andvari.hostile

import io.silencelen.andvari.cli.e2e.accept
import io.silencelen.andvari.cli.e2e.connect
import io.silencelen.andvari.cli.e2e.doc
import io.silencelen.andvari.cli.e2e.ok
import io.silencelen.andvari.cli.e2e.synced
import io.silencelen.andvari.core.client.log.LogAction
import io.silencelen.andvari.core.client.log.StoredVaultLogs
import io.silencelen.andvari.core.model.wire.WireRoute
import io.silencelen.andvari.hostile.proxy.refuse
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * A second device of one account, against the real server (design §3.6, §5.4, §8.5): Bob accepts Alice's vault on the
 * device that connected with her; his other devices, signed in with the password only (no current contacts), get the
 * vault by themselves through the self-wrap the first one posted and the answer it recorded in the account state.
 *
 * Such a device once answered "connect first" for a vault Bob had accepted (its adoption read the answer
 * from the device's own copy of the account state, which no sync read). Core's `SecondDeviceTest` pins every order at
 * the shared code's own level; this is the same journey over the wire, with the self-wrap's post lost once.
 */
class SecondDeviceTest {
    @Test fun aPasswordOnlySecondDeviceGetsTheVaultTheAccountAcceptedByItselfWhicheverItSignedInFirst() = world {
        operator()
        val ah = member("alice")
        val bh = member("bob")
        connect(ah, bh, origin)
        val a = account(ah)
        val b = account(bh)
        a.synced()
        val v = a.ok(null, LogAction.Create("Family"))
        assertEquals(null, a.putItem(v, doc("before the add")).second)
        a.ok(v, LogAction.Add(b.userId, "writer"))

        // Signed in before the accept: nothing of the vault is read, nothing is asked.
        val early = account(passwordDevice("bob2", "bob@example.org"))
        early.synced()
        assertNull(early.vaultName(v), "before the accept")

        // The first device accepts, and its self-wrap's post is lost (the server never sees it): the vault's key is
        // nowhere a password-only device can open it yet.
        val lost = proxy.on(WireRoute.VAULT_SELF_WRAP, "bob", handler = refuse(500, "internal"))
        accept(b, v, "Family")
        lost.remove()
        assertEquals(1, sent(bh, WireRoute.VAULT_SELF_WRAP).size)
        assertEquals(null, a.putItem(v, doc("after the accept")).second)
        early.synced()
        assertNull(early.vaultName(v), "no self-wrap stored yet")

        // The first device's next sync after the retry interval posts it again.
        server.advance(StoredVaultLogs.WRAP_RETRY_MS)
        b.synced()
        assertEquals(2, sent(bh, WireRoute.VAULT_SELF_WRAP).size, "the lost post is made again")

        // Signed in after the accept, and the one signed in before: both read the vault and every item in it.
        val late = account(passwordDevice("bob3", "bob@example.org"))
        for ((what, s) in listOf("signed in before the accept" to early, "signed in after it" to late)) {
            s.synced()
            assertEquals("Family", s.vaultName(v), what)
            val names = s.items.items().filter { it.vaultId == v }.map { it.doc.name }.toSet()
            assertEquals(setOf("before the add", "after the accept"), names, what)
            assertTrue(s.writeAllowed(v), "$what: a writer writes")
        }
        // Neither second device posted a wrap of its own or was asked anything: it sent nothing to the vault's log.
        for (tag in listOf("bob2", "bob3")) {
            assertEquals(0, proxy.requests(WireRoute.VAULT_SELF_WRAP, tag).size, tag)
            assertEquals(0, proxy.requests(WireRoute.LOG_APPEND, tag).size, tag)
        }
    }
}
