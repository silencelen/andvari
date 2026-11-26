package io.silencelen.andvari.hostile

import io.silencelen.andvari.cli.Host
import io.silencelen.andvari.cli.SyncOutcome
import io.silencelen.andvari.cli.e2e.synced
import io.silencelen.andvari.core.client.net.BODY_OVER_LIMIT
import io.silencelen.andvari.core.client.net.ResponseCaps
import io.silencelen.andvari.core.client.net.WireResult
import io.silencelen.andvari.core.client.account.Fetched
import io.silencelen.andvari.core.client.pin.FirstPin
import io.silencelen.andvari.core.client.pin.PinState
import io.silencelen.andvari.core.client.pin.TrustGateWording
import io.silencelen.andvari.core.model.wire.WireRoute
import io.silencelen.andvari.hostile.proxy.Endless
import io.silencelen.andvari.hostile.proxy.Exchange
import io.silencelen.andvari.hostile.proxy.Resp
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue

/**
 * Every answer is read up to a cap that fits its route ([ResponseCaps]), before a Trust Gate as after
 * it. A hostile server answers four routes with a body that never ends, once declaring a length far above the cap and
 * once with none (chunked): the card chain before the Trust Gate, the client policy, a sync, and a vault log page. Each
 * is refused at its cap (`body_over_limit`), the device takes no more than the cap plus what sockets buffer, and nothing
 * of the answer is kept: the device state is what it was.
 */
class AnswerCapsTest {
    /** The two endless answers to a route of cap [cap]: by a lying length, and with no length at all. */
    private fun lies(cap: Long) = listOf(
        "by length" to Endless(declaredLength = 1L shl 40, upTo = cap + (64L shl 20)),
        "with no length" to Endless(declaredLength = null, upTo = cap + (64L shl 20)),
    )

    /** What may reach the device beyond the cap before it hangs up: what the sockets and the engine buffer. */
    private val buffered = 16L shl 20

    private fun World.endless(route: WireRoute, tag: String, lie: Endless) =
        proxy.on(route, tag) { _ -> Resp(200, mapOf("Content-Type" to "application/json"), ByteArray(0), lie) }

    private fun World.took(route: WireRoute, mark: Int, what: String): List<Exchange> {
        val exs = proxy.since(mark).filter { it.req.route == route }
        assertTrue(exs.isNotEmpty(), "$what: $route was asked")
        val cap = ResponseCaps.of(route)
        for (ex in exs) assertTrue(ex.written <= cap + buffered, "$what: the device took ${ex.written} bytes of $route, cap $cap")
        return exs
    }

    private fun snapshot(h: Host): Map<String, String?> = h.state.keys()!!.associateWith { h.state.get(it) }

    @Test fun anEndlessCardChainBeforeTheTrustGateIsRefusedAtItsCapAndNothingIsPinned() = world {
        operator()
        for ((what, lie) in lies(ResponseCaps.CARD_CHAIN)) {
            val bob = device("bob-${what.replace(' ', '-')}")
            val tag = tag(bob)
            val rule = endless(WireRoute.INSTANCE, tag, lie)
            val before = snapshot(bob)
            val mark = proxy.mark()
            val gate = bob.trust.beginTrustGate(origin, TrustGateWording.TYPED_ADDRESS)
            assertTrue(gate !is FirstPin.NeedsTrustGate && gate !is FirstPin.Pinned, "$what: no Trust Gate from an endless chain: $gate")
            val direct = bob.client(origin).call(WireRoute.INSTANCE, decode = { error("nothing of it is decoded") })
            assertEquals(BODY_OVER_LIMIT, assertIs<WireResult.Refused>(direct, "$what: $direct").code)
            took(WireRoute.INSTANCE, mark, what)
            assertEquals(PinState.None, bob.trust.pinState(origin), "$what: nothing is pinned")
            assertEquals(before, snapshot(bob), "$what: nothing of the answer is kept")
            // The honest chain still pins.
            rule.remove()
            assertIs<FirstPin.NeedsTrustGate>(bob.trust.beginTrustGate(origin, TrustGateWording.TYPED_ADDRESS), what)
        }
    }

    @Test fun anEndlessPolicyIsRefusedAtItsCap() = world {
        operator()
        val ah = member("alice")
        for ((what, lie) in lies(ResponseCaps.of(WireRoute.CLIENT_POLICY))) {
            val rule = endless(WireRoute.CLIENT_POLICY, "alice", lie)
            val before = snapshot(ah)
            val mark = proxy.mark()
            val offer = ah.onboarding(origin).signupOffer()
            assertTrue(offer !is Fetched.Ok, "$what: $offer")
            val direct = ah.client(origin).call(WireRoute.CLIENT_POLICY, decode = { error("nothing of it is decoded") })
            assertEquals(BODY_OVER_LIMIT, assertIs<WireResult.Refused>(direct, "$what: $direct").code)
            took(WireRoute.CLIENT_POLICY, mark, what)
            assertEquals(before, snapshot(ah), "$what: nothing of the answer is kept")
            rule.remove()
        }
        assertIs<Fetched.Ok<*>>(ah.onboarding(origin).signupOffer(), "the honest policy still reads")
    }

    @Test fun anEndlessSyncIsRefusedAtItsCapAndTheCopyStaysAsItWas() = world {
        operator()
        val ah = member("alice")
        val a = account(ah)
        a.synced()
        val items = a.items(a.personalVaultId!!)
        for ((what, lie) in lies(ResponseCaps.SYNC)) {
            val rule = endless(WireRoute.SYNC, "alice", lie)
            val before = snapshot(ah)
            val mark = proxy.mark()
            val r = a.sync()
            assertTrue(r !is SyncOutcome.Synced, "$what: $r")
            took(WireRoute.SYNC, mark, what)
            assertEquals(before, snapshot(ah), "$what: nothing of the answer is kept")
            assertEquals(items, a.items(a.personalVaultId!!), "$what: the copy is unchanged")
            rule.remove()
        }
        a.synced()
    }

    @Test fun anEndlessLogPageIsRefusedAtItsCapAndTheVerifiedLogStaysAsItWas() = world {
        operator()
        val ah = member("alice")
        val bh = member("bob")
        val v = sharedVault(ah, bh)
        val b = account(bh)
        b.synced()
        val status = b.logs.status(v)
        for ((what, lie) in lies(ResponseCaps.LOG_PAGE)) {
            val rule = endless(WireRoute.LOG_FETCH, "bob", lie)
            val before = snapshot(bh)
            val mark = proxy.mark()
            b.logs.refresh(v, null, null, force = true)
            took(WireRoute.LOG_FETCH, mark, what)
            assertEquals(status, b.logs.status(v), "$what: the verified log is unchanged")
            assertEquals(before, snapshot(bh), "$what: nothing of the answer is kept")
            rule.remove()
        }
        b.synced()
        assertTrue(b.writeAllowed(v), "the shared vault still works")
    }
}
