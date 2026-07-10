package io.silencelen.andvari.core.client

import io.silencelen.andvari.core.crypto.KdfParams
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * F61 KDF-upgrade decision (spec 01 §7, design 2026-07-10 §4). Pure integer comparison — no
 * crypto — so the whole truth table runs in the common gate. The security property under test:
 * a hostile `/client-policy` can never coax `shouldUpgrade` into true for a weakening, a
 * sideways move, or an absurd cost (spec 05 T1).
 */
class KdfUpgradeTest {
    private fun params(ops: Long, memMiB: Long) = KdfParams(ops = ops, memBytes = memMiB * 1024 * 1024)

    private val floor = params(ops = 3, memMiB = 64) // the §9 floor / v1 default.

    @Test
    fun equalParamsIsNoUpgrade() {
        assertFalse(KdfUpgrade.shouldUpgrade(floor, floor))
    }

    @Test
    fun bothAxesUpIsUpgrade() {
        assertTrue(KdfUpgrade.shouldUpgrade(floor, params(ops = 4, memMiB = 128)))
    }

    @Test
    fun singleAxisUpIsUpgrade() {
        // ops up, mem equal.
        assertTrue(KdfUpgrade.shouldUpgrade(floor, params(ops = 4, memMiB = 64)))
        // mem up, ops equal.
        assertTrue(KdfUpgrade.shouldUpgrade(floor, params(ops = 3, memMiB = 128)))
    }

    @Test
    fun strictDowngradeIsRefused() {
        val strong = params(ops = 5, memMiB = 256)
        assertFalse(KdfUpgrade.shouldUpgrade(strong, params(ops = 4, memMiB = 128)))
        assertFalse(KdfUpgrade.shouldUpgrade(strong, floor))
    }

    @Test
    fun mixedParamsNeverConverge() {
        // Both endpoints inside the sanity fence, so the fence is NOT what rejects them — the
        // dominate-on-both-axes rule is. Neither direction is an upgrade: the partial-order gap.
        val a = params(ops = 4, memMiB = 128)
        val b = params(ops = 5, memMiB = 64)
        assertFalse(KdfUpgrade.shouldUpgrade(a, b)) // ops up, mem down
        assertFalse(KdfUpgrade.shouldUpgrade(b, a)) // mem up, ops down
    }

    @Test
    fun policyBelowFloorIsRefused() {
        // 32 MiB policy would be a weakening even though it "dominates" a below-floor account.
        val belowFloorAccount = params(ops = 2, memMiB = 16)
        assertFalse(KdfUpgrade.shouldUpgrade(belowFloorAccount, params(ops = 3, memMiB = 32)))
        // ops below the floor likewise refused.
        assertFalse(KdfUpgrade.shouldUpgrade(belowFloorAccount, KdfParams(ops = 2, memBytes = 64L * 1024 * 1024)))
    }

    @Test
    fun policyAboveCeilingIsRefused() {
        // 2 GiB / ops 50 — a cost-inflation DoS, refused even though it dominates the account.
        assertFalse(KdfUpgrade.shouldUpgrade(floor, KdfParams(ops = 50, memBytes = 2L * 1024 * 1024 * 1024)))
        // Each ceiling independently: absurd mem alone, absurd ops alone.
        assertFalse(KdfUpgrade.shouldUpgrade(floor, KdfParams(ops = 3, memBytes = 2L * 1024 * 1024 * 1024)))
        assertFalse(KdfUpgrade.shouldUpgrade(floor, params(ops = 11, memMiB = 128)))
    }

    @Test
    fun exactBoundsAreAcceptedAsUpgradeTargets() {
        // A below-floor account may upgrade exactly TO the floor, and up to the ceiling — the
        // fence is inclusive at both ends.
        val tiny = KdfParams(ops = 1, memBytes = 8192)
        assertTrue(KdfUpgrade.shouldUpgrade(tiny, floor))
        assertTrue(KdfUpgrade.shouldUpgrade(floor, KdfParams(ops = KdfUpgrade.MAX_OPS, memBytes = KdfUpgrade.MAX_MEM_BYTES)))
    }
}
