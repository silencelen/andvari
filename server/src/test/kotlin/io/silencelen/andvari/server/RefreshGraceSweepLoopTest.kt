package io.silencelen.andvari.server

import io.ktor.server.testing.testApplication
import io.silencelen.andvari.core.model.wire.TokenPair
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * The server's own once-a-second sweep of the refresh grace (spec 03 §2): a pair kept for a repeated refresh is dropped
 * once its minute has passed even on a server where nothing else is refreshed or looked up. The sweep itself is tested
 * in [RefreshGraceTest]; this test is about its wiring: started with the server, it calls the sweep. It fails when the
 * server starts without the loop, or with a loop that never calls the sweep.
 */
class RefreshGraceSweepLoopTest {
    private fun waitForEmpty(grace: RefreshGrace, ms: Long) {
        val deadline = System.nanoTime() + ms * 1_000_000
        while (grace.size > 0 && System.nanoTime() < deadline) Thread.sleep(50)
    }

    @Test
    fun theServerStartsTheSweep_andItDropsAPairPastItsMinute_withNoOtherRequest() = testApplication {
        val clock = MutableClock(1_800_000_000_000L)
        val s = TestKit.services(clock = clock).also { it.backgroundWorkers = true }
        application { andvariModule(s) }
        startApplication()
        val grace = s.sessions.refreshGrace
        grace.record("spent", TokenPair("access", "refresh"), "session", "device")
        clock.advance(RefreshGrace.WINDOW_MS + 1)
        // Nothing but the server's loop touches the grace from here on.
        waitForEmpty(grace, 10_000)
        assertEquals(0, grace.size, "the server's loop dropped the pair within seconds")
    }

    /** The control: the same server with its background work off keeps the pair, so only the loop can have dropped it. */
    @Test
    fun withoutTheLoop_thePairStays() = testApplication {
        val clock = MutableClock(1_800_000_000_000L)
        val s = TestKit.services(clock = clock)
        application { andvariModule(s) }
        startApplication()
        val grace = s.sessions.refreshGrace
        grace.record("spent", TokenPair("access", "refresh"), "session", "device")
        clock.advance(RefreshGrace.WINDOW_MS + 1)
        waitForEmpty(grace, 2_500)
        assertEquals(1, grace.size)
    }
}
