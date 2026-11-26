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

    private val kib = 1024L
    private val floorMem = KdfUpgrade.MIN_MEM_BYTES
    private val ceilMem = KdfUpgrade.MAX_MEM_BYTES

    /** One row: the account's cost, the policy's, and whether a re-key is due. */
    private class Row(val name: String, val account: KdfParams, val policy: KdfParams, val due: Boolean)

    private fun row(name: String, aOps: Long, aMem: Long, pOps: Long, pMem: Long, due: Boolean) =
        Row(name, KdfParams(ops = aOps, memBytes = aMem), KdfParams(ops = pOps, memBytes = pMem), due)

    /** Every edge of spec 01 §7's rule, each by one step of the smallest unit on either side. */
    private val edges = listOf(
        row("equal at the floor", 3, floorMem, 3, floorMem, false),
        row("equal above the floor", 5, 256 * kib * kib, 5, 256 * kib * kib, false),
        row("memory up one KiB, passes equal", 3, floorMem, 3, floorMem + kib, true),
        row("passes up one, memory equal", 3, floorMem, 4, floorMem, true),
        row("both up", 3, floorMem, 4, floorMem + kib, true),
        row("memory down one KiB, passes equal", 3, floorMem + kib, 3, floorMem, false),
        row("passes down one, memory equal", 4, floorMem, 3, floorMem, false),
        row("both down", 4, floorMem + kib, 3, floorMem, false),
        row("mixed: passes up, memory down one KiB", 3, floorMem + kib, 4, floorMem, false),
        row("mixed: memory up, passes down one", 4, floorMem, 3, floorMem + kib, false),
        row("policy one KiB below the memory floor, over a weaker account", 1, 8 * kib, 3, floorMem - kib, false),
        row("policy one pass below the pass floor, over a weaker account", 1, 8 * kib, 2, floorMem, false),
        row("policy exactly at the floor, over a weaker account", 1, 8 * kib, 3, floorMem, true),
        row("policy exactly at both ceilings", 3, floorMem, KdfUpgrade.MAX_OPS, ceilMem, true),
        row("policy one KiB above the memory ceiling", 3, floorMem, 3, ceilMem + kib, false),
        row("policy one pass above the pass ceiling", 3, floorMem, KdfUpgrade.MAX_OPS + 1, floorMem, false),
        row("policy far above both ceilings", 3, floorMem, 50, 2 * ceilMem, false),
        row("account above the ceiling, policy at it", 12, 2 * ceilMem, KdfUpgrade.MAX_OPS, ceilMem, false),
        row("memory up by one byte: not a whole KiB", 3, floorMem, 3, floorMem + 1, false),
        row("memory up by half a KiB with a pass more: not a whole KiB", 3, floorMem, 4, floorMem + 512, false),
        row("memory at the ceiling less one byte", 3, floorMem, 3, ceilMem - 1, false),
    )

    @Test
    fun everyEdgeOfTheRuleIsDecidedAsTheSpecificationSays() {
        val wrong = edges.filter { KdfUpgrade.shouldUpgrade(it.account, it.policy) != it.due }.map { it.name }
        assertTrue(wrong.isEmpty(), "decided wrongly: $wrong")
    }

    /**
     * Over a grid of costs at and around every bound, a re-key is due exactly when the policy is inside the fence, a whole
     * number of KiB, at least the account's on both axes and above it on one: never a lower, mixed, absurd or ragged cost.
     */
    @Test
    fun aDueReKeyNeverWeakensNeverInflatesAndNeverGoesSideways() {
        val opsGrid = listOf(1L, 2L, 3L, 4L, 9L, 10L, 11L, 50L)
        val memGrid = listOf(8 * kib, floorMem - kib, floorMem - 1, floorMem, floorMem + 1, floorMem + kib, 256 * kib * kib, ceilMem - kib, ceilMem, ceilMem + 1, ceilMem + kib)
        val params = opsGrid.flatMap { o -> memGrid.map { m -> KdfParams(ops = o, memBytes = m) } }
        var due = 0
        for (a in params) for (p in params) {
            val inFence = p.ops in KdfUpgrade.MIN_OPS..KdfUpgrade.MAX_OPS && p.memBytes in floorMem..ceilMem
            val expected = inFence && p.memBytes % kib == 0L && p.ops >= a.ops && p.memBytes >= a.memBytes && (p.ops > a.ops || p.memBytes > a.memBytes)
            val got = KdfUpgrade.shouldUpgrade(a, p)
            if (got) due++
            assertTrue(got == expected, "account ${a.ops}/${a.memBytes}, policy ${p.ops}/${p.memBytes}: $got")
        }
        assertTrue(due > 0)
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
