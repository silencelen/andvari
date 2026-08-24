package io.silencelen.andvari.app

import io.silencelen.andvari.app.SessionStore.Companion.QU_REOFFER_AFTER
import io.silencelen.andvari.app.SessionStore.Companion.QU_REOFFER_MAX
import io.silencelen.andvari.app.SessionStore.Companion.ReofferInputs
import io.silencelen.andvari.app.SessionStore.Companion.reofferDecision
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * The quick-unlock re-offer decision (design 2026-08-23 §7.1), pinned pure — the
 * [QuickUnlock.isFreshPure] idiom, so every boundary is testable without SharedPreferences.
 *
 * Why this exists at all: the enrollment offer was one-and-done, and "Not now" silenced it
 * forever. That was correct while backgrounding did not lock — the user typed their master
 * password rarely. Lock-on-background changed that trade AFTER some users had already dismissed
 * the offer, and a choice made under the old cost should not bind them to the new one.
 *
 * The hard part is re-offering without becoming the nag loop the original design was avoiding.
 * These tests pin both halves of that: it DOES come back when the user has visibly paid the
 * cost, and it DOES eventually stop for good.
 */
class QuickUnlockReofferTest {

    @Test
    fun aVisibleOfferNeverCounts() {
        // Nothing to re-open — and counting here would let one ignored card burn the whole budget.
        val out = reofferDecision(ReofferInputs(dismissed = false, unlocks = 0, reoffers = 0))
        assertFalse(out.reoffer)
        assertEquals(0, out.unlocks, "an un-dismissed offer must not accumulate evidence")
    }

    @Test
    fun theOfferReturnsOnlyAfterTheCostIsPaidTheFullNumberOfTimes() {
        var cur = ReofferInputs(dismissed = true, unlocks = 0, reoffers = 0)
        // The first QU_REOFFER_AFTER - 1 unlocks accumulate silently.
        repeat(QU_REOFFER_AFTER - 1) {
            val out = reofferDecision(cur)
            assertFalse(out.reoffer, "re-offered early, at ${out.unlocks} unlocks")
            cur = ReofferInputs(true, out.unlocks, out.reoffers)
        }
        // The QU_REOFFER_AFTER-th earns it.
        val out = reofferDecision(cur)
        assertTrue(out.reoffer)
        assertEquals(1, out.reoffers)
        assertEquals(0, out.unlocks, "the counter resets, so the NEXT re-offer must be earned again")
    }

    @Test
    fun eachReofferMustBeEarnedAgainFromZero() {
        // Straight after a re-offer, one more unlock must not immediately produce another.
        val afterFirst = ReofferInputs(dismissed = true, unlocks = 0, reoffers = 1)
        assertFalse(reofferDecision(afterFirst).reoffer)
    }

    /** The no-nag-loop property, stated as an assertion: a user who keeps declining is left
     *  alone permanently, and the lifetime total is bounded. */
    @Test
    fun pastTheCapItIsInertForever() {
        val maxed = ReofferInputs(dismissed = true, unlocks = 0, reoffers = QU_REOFFER_MAX)
        // Far more unlocks than could ever be needed — still nothing.
        var cur = maxed
        repeat(QU_REOFFER_AFTER * 20) {
            val out = reofferDecision(cur)
            assertFalse(out.reoffer, "re-offered past the cap")
            cur = ReofferInputs(true, out.unlocks, out.reoffers)
        }
        assertEquals(QU_REOFFER_MAX, cur.reoffers)
    }

    /** The lifetime bound the user actually experiences: the original card plus QU_REOFFER_MAX. */
    @Test
    fun aUserWhoDeclinesEverythingSeesABoundedNumberOfCards() {
        // Simulate a lifetime of password unlocks with the user dismissing every re-offer.
        var cur = ReofferInputs(dismissed = true, unlocks = 0, reoffers = 0)
        var cards = 0
        repeat(500) {
            val out = reofferDecision(cur)
            if (out.reoffer) cards++
            // Dismissed again immediately — the pessimistic user.
            cur = ReofferInputs(dismissed = true, unlocks = out.unlocks, reoffers = out.reoffers)
        }
        assertEquals(QU_REOFFER_MAX, cards, "re-offers must be capped at QU_REOFFER_MAX over any lifetime")
    }

    /** The constants are the product decision, so a change to them is a deliberate act. */
    @Test
    fun theTuningIsWhatTheDesignSaid() {
        assertEquals(3, QU_REOFFER_AFTER, "three paid costs before the offer returns")
        assertEquals(2, QU_REOFFER_MAX, "at most two re-offers — three cards in a lifetime")
    }
}
