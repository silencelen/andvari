package io.silencelen.andvari.core.crypto

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

/**
 * The AD twin (spec 02 §2) for the usage ledger — the Kotlin half of the pair pinned in
 * web/src/vault/usage.test.ts. There is no shared vector between the two hand-mirrored
 * one-liners, and a silent divergence has a nasty shape: each client would seal and open its OWN
 * ledger perfectly while being unable to open the other's, so the symptom would read as "the
 * phone just never records anything" rather than as a crypto fault. Both sides pin the literal.
 */
class AdUsageTest {

    @Test
    fun usageAdIsTheExactSpecString() {
        assertEquals("andvari/v1|usage|u1", Ad.usage("u1").decodeToString())
    }

    @Test
    fun usageAdRefusesASeparatorInTheUserId() {
        assertFailsWith<IllegalArgumentException> { Ad.usage("a|b") }
    }
}
