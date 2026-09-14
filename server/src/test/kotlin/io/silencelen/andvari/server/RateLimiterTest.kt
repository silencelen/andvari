package io.silencelen.andvari.server

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Fixed-window behavior + the amortized eviction (polish audit 2026-07-27 bug-server--3):
 * expired windows are swept every PRUNE_EVERY calls, so the per-IP keys minted on
 * public-reachable routes can no longer grow the map for the process lifetime — the same
 * bounding discipline sibling [EmailBackoff] already carries (review 2026-07-16 D2).
 *
 * Time is DRIVEN here, never slept through (H97, audit 2026-09-13). Both tests used to race a
 * real 50 ms / 1 ms window: four calls had to complete inside one window on a JIT-cold JVM, and
 * a `Thread.sleep(5)` had to actually outlast a 1 ms window. Neither can go green over a real
 * regression, but both could go RED on a loaded 8-12 GB build host — and an intermittently red
 * gate is one that gets re-run until it passes, which is precisely the baseline the audits lean
 * on. The window arithmetic is unchanged; only the clock is now explicit.
 */
class RateLimiterTest {

    /** A hand-cranked clock: no wall-clock time enters these tests at all. */
    private class FakeClock(var ms: Long = 1_000_000L) : () -> Long {
        override fun invoke(): Long = ms
        fun advance(by: Long) { ms += by }
    }

    @Test
    fun fixedWindow_limitsThenResetsAfterExpiry() {
        val clock = FakeClock()
        val rl = RateLimiter(clock)
        repeat(3) { assertTrue(rl.allow("k", 3, 50)) }
        assertFalse(rl.allow("k", 3, 50), "the 4th call inside the window must be refused")
        // Still inside the window one tick before it lapses — the boundary the old sleep could
        // never pin, because it could only ever wait LONGER than intended.
        clock.advance(49)
        assertFalse(rl.allow("k", 3, 50), "the window has not lapsed yet")
        clock.advance(1)
        assertTrue(rl.allow("k", 3, 50), "an expired window must reset in place")
    }

    @Test
    fun prune_evictsExpiredWindows_keepsLiveOnes() {
        val clock = FakeClock()
        val rl = RateLimiter(clock)
        // 100 distinct short-window keys — the attacker-expandable per-IP shape…
        repeat(100) { rl.allow("stale-$it", 5, 1) }
        clock.advance(5) // …all expired now.
        // Cross the amortization threshold on a LIVE key so the sweep runs inside this loop.
        repeat(RateLimiter.PRUNE_EVERY) { rl.allow("live", Int.MAX_VALUE, 60_000) }
        assertEquals(1, rl.size(), "expired windows must be evicted; the live one kept")
        // Eviction is behavior-free: an evicted key re-admits exactly like an in-place reset…
        assertTrue(rl.allow("stale-0", 1, 60_000))
        // …and then rate-limits normally again.
        assertFalse(rl.allow("stale-0", 1, 60_000))
    }

    /**
     * The default clock is the real one — production is not accidentally frozen.
     *
     * R25: this must assert ELAPSED TIME, not just that limiting happens. Walk the old shape
     * against a hypothetical frozen default `clock = { 0L }`: the first call creates the window
     * and admits, the second sees `0 - 0 < 60_000` and refuses — both assertions pass, so the one
     * test guarding the injected-clock default could not detect the one thing it claimed to guard.
     * A frozen clock is not a hypothetical either: it is what every OTHER test in this file passes
     * in, so a fat-fingered default would look exactly like the rest of the suite.
     *
     * Direction matters for flakiness (the H97 rule): the banned shape required work to finish
     * INSIDE a window, which goes red on a loaded or JIT-cold host over no regression at all.
     * Waiting LONGER than a 1 ms window cannot fail that way — a slow host only waits longer.
     */
    @Test
    fun defaultClock_isWallClock() {
        val rl = RateLimiter()
        // It still limits — asserted on a 60 s window, which assumes nothing about how long the
        // two calls take (the flaky shape would be a SHORT window here).
        assertTrue(rl.allow("limits", 1, 60_000))
        assertFalse(rl.allow("limits", 1, 60_000), "a real-clock limiter still limits")
        // …and the clock ADVANCES: a 1 ms window must reopen after a real sleep. Only the
        // wait-longer direction is asserted, so a slow host can only make this MORE true.
        assertTrue(rl.allow("ticks", 1, 1))
        Thread.sleep(25)
        assertTrue(rl.allow("ticks", 1, 1), "the default clock must ADVANCE — a frozen one never reopens the window")
    }
}
