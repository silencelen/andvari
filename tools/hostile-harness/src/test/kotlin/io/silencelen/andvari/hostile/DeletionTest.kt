package io.silencelen.andvari.hostile

import io.silencelen.andvari.cli.e2e.Steps
import io.silencelen.andvari.cli.e2e.accept
import io.silencelen.andvari.cli.e2e.connect
import io.silencelen.andvari.cli.e2e.ok
import io.silencelen.andvari.cli.e2e.synced
import io.silencelen.andvari.core.client.deletion.DeletionOutcome
import io.silencelen.andvari.core.client.log.LogAction
import io.silencelen.andvari.core.client.log.VaultLogStatus
import io.silencelen.andvari.core.model.wire.WireRoute
import io.silencelen.andvari.hostile.proxy.Frames
import io.silencelen.andvari.hostile.proxy.arr
import io.silencelen.andvari.hostile.proxy.edit
import io.silencelen.andvari.hostile.proxy.editAnswer
import io.silencelen.andvari.hostile.proxy.editEach
import io.silencelen.andvari.hostile.proxy.set
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue

/**
 * Account deletion's leaves under a hostile server (design §3.11, FS-R7, T2-R-a). Each leave is placed at a head; a
 * head this device verified is placed from its own state, and any other head is the server's word, held to a bound of
 * one day ahead of the device's clock. So a server cannot obtain an honest far-future `leave` that would freeze the
 * vault's offers.
 */
class DeletionTest {
    private val password get() = Steps.PASSWORD.toCharArray()
    private val farAhead = 2L * 86_400_000L

    /** Every membership in Bob's deletion preview with its head's `at` moved [ahead] into the future. */
    private fun World.previewAhead(ahead: Long) = proxy.on(WireRoute.ACCOUNT_DELETE_PREVIEW, "bob", handler = editAnswer { body ->
        body.editEach("memberships") { m -> m.edit("head") { it.set("at", server.now() + ahead) } }
    })

    /**
     * §3.11 FS-R7: "From an unverified head, the device refuses a `head.at` more than one day ahead of its own clock. It
     * signs nothing for that vault, and the deletion stops." Bob was added to a vault and never synced since, so he
     * holds no verified head for it; the preview names its head two days ahead. Nothing is signed, no proof of the
     * password is sent, and the deletion is not posted. Served the true time, the deletion goes through.
     */
    @Test fun aFarFutureHeadBobNeverVerifiedStopsTheDeletionBeforeAnythingIsSignedOrSent() = world {
        operator()
        val ah = member("alice")
        val bh = member("bob")
        val a = account(ah)
        val b = account(bh)
        connect(ah, bh, origin)
        a.synced()
        val v = a.ok(null, LogAction.Create("Family"))
        a.ok(v, LogAction.Add(b.userId, "writer"))
        assertIs<VaultLogStatus.Unknown>(b.logs.status(v), "Bob holds no verified head for the vault")

        val lie = previewAhead(farAhead)
        val mark = proxy.mark()
        assertEquals(DeletionOutcome.FutureHead, b.deletion {}.delete("bob@example.org", password, null))
        assertTrue(sent(bh, WireRoute.ACCOUNT_DELETE, mark).isEmpty(), "the deletion is not posted")
        assertTrue(secretSends("bob", mark).isEmpty(), "no proof of the password is derived or sent: ${secretSends("bob", mark)}")

        lie.remove()
        assertIs<DeletionOutcome.Deleted>(b.deletion {}.delete("bob@example.org", password, null))
        val leave = Frames.statement(sent(bh, WireRoute.ACCOUNT_DELETE).single().json!!.arr("leaves")!!.single().jsonPrimitive.content)
        assertEquals("leave", leave["kind"]!!.jsonPrimitive.content)
        assertTrue(leave["at"]!!.jsonPrimitive.long <= server.now() + 10 * 60_000L, "the leave is placed at the true time")
    }

    /**
     * §3.11: a head this device verified is placed from its own verified state; "the served `at` beside a verified
     * (seq, hash) is the server's word and is never signed after". Bob verified the vault's head; the preview names the
     * same position two days ahead. The deletion goes through with a leave at Bob's own time, and the owner verifies it.
     */
    @Test fun aFarFutureTimeOnAHeadBobVerifiedIsIgnoredAndTheLeaveCarriesHisOwnTime() = world {
        operator()
        val ah = member("alice")
        val bh = member("bob")
        val v = sharedVault(ah, bh)
        val a = account(ah)
        val b = account(bh)
        b.synced()
        assertIs<VaultLogStatus.Verified>(b.logs.status(v))

        previewAhead(farAhead)
        assertIs<DeletionOutcome.Deleted>(b.deletion {}.delete("bob@example.org", password, null))
        val leave = Frames.statement(sent(bh, WireRoute.ACCOUNT_DELETE).single().json!!.arr("leaves")!!.single().jsonPrimitive.content)
        assertTrue(leave["at"]!!.jsonPrimitive.long <= server.now() + 10 * 60_000L, "the leave carries the device's own time, not the server's: $leave")
        a.synced()
        val after = assertIs<VaultLogStatus.Verified>(a.logs.status(v), "the owner verifies Bob's leave").state
        assertEquals(setOf(a.userId), after.members.keys, "Bob left, by his own signed entry")
    }
}
