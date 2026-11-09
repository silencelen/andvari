package io.silencelen.andvari.core.client

import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Security review 2026-10, branch A12 (desktop row 80 and its Android twin): a policy reply is only
 * applied when it belongs to the origin the app is dialing NOW, and to the probe generation that
 * origin was entered under. Both clients share this one fence.
 */
class OriginProbeFenceTest {
    @Test
    fun aReplyFromTheCurrentOriginAndGenerationApplies() {
        val f = OriginProbeFence()
        val t = f.tag("home")
        assertTrue(f.isCurrent(t, "home"))
    }

    @Test
    fun aReplyFromAnAbandonedOriginIsDropped() {
        val f = OriginProbeFence()
        val hostile = f.tag("hostile")
        f.advance() // the user cancelled back to home
        assertFalse(f.isCurrent(hostile, "home"), "a late reply from the abandoned origin must not apply")
        assertFalse(f.isCurrent(hostile, "hostile"), "even if the app later dials that origin again, an OLD probe's reply is stale")
    }

    @Test
    fun aRoundTripBackToTheSameOriginStillDropsTheOldProbe() {
        // home -> hostile -> home: the first home probe's reply carries home's key but an old
        // generation. Generation, not origin, is what proves it is THIS visit's answer.
        val f = OriginProbeFence()
        val first = f.tag("home")
        f.advance(); f.advance()
        assertFalse(f.isCurrent(first, "home"))
        assertTrue(f.isCurrent(f.tag("home"), "home"))
    }

    @Test
    fun theOriginMustMatchEvenWithinOneGeneration() {
        val f = OriginProbeFence()
        assertFalse(f.isCurrent(f.tag("a"), "b"))
    }
}
