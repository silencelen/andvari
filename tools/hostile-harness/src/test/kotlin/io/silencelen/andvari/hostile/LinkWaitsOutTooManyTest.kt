package io.silencelen.andvari.hostile

import io.silencelen.andvari.cli.Host
import io.silencelen.andvari.cli.e2e.Steps
import io.silencelen.andvari.core.client.devicelink.ExistingStep
import io.silencelen.andvari.core.client.devicelink.NewStep
import io.silencelen.andvari.core.client.pin.GateEntry
import io.silencelen.andvari.core.model.wire.WireRoute
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertSame
import kotlin.test.assertTrue

/**
 * Two new devices linking at the same time behind one address share the REAL server's budget for a waiting link's polls
 * (60 a minute per caller address, the poll and the reveal together), and can reach it. A poll refused as too many is
 * waited out as long as the answer says and asked again: neither link stops, and both end linked. Before, the first
 * refusal stopped that link (the new device read it as an unreachable server), and the person had to start again.
 */
class LinkWaitsOutTooManyTest {
    private class Waiting(val eh: Host, val nh: Host, val fixed: ExistingStep.ClaimFixed, val code: NewStep.ShowCode)

    private suspend fun World.waiting(eh: Host, tag: String): Waiting {
        val nh = device(tag)
        val shown = assertIs<ExistingStep.Shown>(eh.deviceLinks.create(), "${tag(eh)} shows a link")
        var n = nh.deviceLinks.start(shown.url, GateEntry.LINK_DEVICE_SCREEN)
        if (n is NewStep.TrustGate) n = nh.deviceLinks.afterTrustGate(n, confirmed = true)
        val claimed = assertIs<NewStep.Claimed>(n, "$tag claims: $n")
        val fixed = assertIs<ExistingStep.ClaimFixed>(eh.deviceLinks.advance(shown))
        val code = assertIs<NewStep.ShowCode>(nh.deviceLinks.advance(claimed), "$tag reveals and shows its code")
        return Waiting(eh, nh, fixed, code)
    }

    @Test fun twoNewDevicesBehindOneAddressWaitOutARefusalForTooManyPollsAndBothLink() = world {
        operator()
        val alice = member("alice")
        val bob = member("bob")
        val links = listOf(waiting(alice, "n1"), waiting(bob, "n2"))

        // Both new devices wait on their screens, polling at the same time from one address, until the server refuses one.
        val mark = proxy.mark()
        var refused: Waiting? = null
        for (round in 0 until 60) {
            for (w in links) {
                val before = proxy.mark()
                val next = w.nh.deviceLinks.advance(w.code)
                assertEquals(w.code.code, assertIs<NewStep.ShowCode>(next, "${tag(w.nh)} is still waiting (round $round): $next").code)
                if (proxy.since(before).any { it.req.route == WireRoute.DEVICE_LINK_POLL && it.upstream?.status == 429 }) refused = w
            }
            if (refused != null) break
        }
        val r = assertNotNull(refused, "the shared budget was reached: ${proxy.since(mark).count { it.req.route == WireRoute.DEVICE_LINK_POLL }} polls")
        val answer = proxy.since(mark).last { it.req.route == WireRoute.DEVICE_LINK_POLL && it.upstream?.status == 429 }.upstream!!
        val wait = assertNotNull(answer.headers.entries.firstOrNull { it.key.equals("Retry-After", ignoreCase = true) }?.value?.toLongOrNull(), "the refusal names its wait")

        // Nothing is asked again before the wait is over.
        val polls = sent(r.nh, WireRoute.DEVICE_LINK_POLL).size
        assertSame(r.code, r.nh.deviceLinks.advance(r.code))
        assertEquals(polls, sent(r.nh, WireRoute.DEVICE_LINK_POLL).size, "nothing is asked during the wait")
        server.advance(wait * 1000 + 1)

        // The people type the codes and approve; both new devices then see the approval and link with the password.
        for (w in links) {
            val type = assertIs<ExistingStep.TypeDigits>(w.eh.deviceLinks.advance(w.fixed))
            val ok = assertIs<ExistingStep.Approvable>(w.eh.deviceLinks.typeDigits(type, w.code.code))
            assertIs<ExistingStep.Approved>(w.eh.deviceLinks.approve(ok))
            var step: NewStep = w.code
            for (i in 0 until 5) {
                step = w.nh.deviceLinks.advance(w.code)
                if (step !is NewStep.ShowCode) break
                server.advance(61_000)
            }
            val need = assertIs<NewStep.PasswordNeeded>(step, "${tag(w.nh)} sees the approval: $step")
            assertIs<NewStep.Linked>(w.nh.deviceLinks.pickup(need, Steps.PASSWORD.toCharArray()), "${tag(w.nh)} links")
        }
        assertTrue(proxy.requests(WireRoute.DEVICE_LINK_POLL).isNotEmpty())
    }
}
