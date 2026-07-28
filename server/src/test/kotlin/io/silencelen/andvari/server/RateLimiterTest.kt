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
 */
class RateLimiterTest {

    @Test
    fun fixedWindow_limitsThenResetsAfterExpiry() {
        val rl = RateLimiter()
        repeat(3) { assertTrue(rl.allow("k", 3, 50)) }
        assertFalse(rl.allow("k", 3, 50), "the 4th call inside the window must be refused")
        Thread.sleep(60)
        assertTrue(rl.allow("k", 3, 50), "an expired window must reset in place")
    }

    @Test
    fun prune_evictsExpiredWindows_keepsLiveOnes() {
        val rl = RateLimiter()
        // 100 distinct short-window keys — the attacker-expandable per-IP shape…
        repeat(100) { rl.allow("stale-$it", 5, 1) }
        Thread.sleep(5) // …all expired now.
        // Cross the amortization threshold on a LIVE key so the sweep runs inside this loop.
        repeat(RateLimiter.PRUNE_EVERY) { rl.allow("live", Int.MAX_VALUE, 60_000) }
        assertEquals(1, rl.size(), "expired windows must be evicted; the live one kept")
        // Eviction is behavior-free: an evicted key re-admits exactly like an in-place reset…
        assertTrue(rl.allow("stale-0", 1, 60_000))
        // …and then rate-limits normally again.
        assertFalse(rl.allow("stale-0", 1, 60_000))
    }
}
