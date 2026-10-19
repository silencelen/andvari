package io.silencelen.andvari.app

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Security review 2026-10, branch A12 (Android): the invite re-point restore point (q06, the twin of
 * desktop row 39) and the quick-unlock 30-day gate under a stepped-back wall clock (row 74).
 */
class A12ClockAndOriginTest {
    private val day = 24L * 60 * 60 * 1000
    private val window = QuickUnlock.WINDOW_MS
    private val stamp = 1_700_000_000_000L

    // ---- row 74: the monotonic check is never skipped because the wall clock moved ----

    /** Same boot, 40 days of real uptime since the stamp, and the holder wound the wall clock back
     *  to stamp+1d. The phone sat dormant, so the high-water mark never advanced past stamp+1d, and
     *  the app reached the server once, a day after the stamp (a real, honest anchor). */
    private fun steppedBackSameBoot() = QuickUnlock.FreshnessInputs(
        nowMs = stamp + day,
        elapsedNowMs = 45 * day,
        stampWallMs = stamp,
        stampElapsedMs = 5 * day,
        stampBootRefMs = stamp - 5 * day,
        highWaterWallMs = stamp + day,
        serverFloorMs = stamp + day,
    )

    @Test
    fun aSteppedBackWallClockCannotReopenTheWindowWithinOneBoot() {
        assertFalse(
            QuickUnlock.isFreshPure(steppedBackSameBoot()),
            "40 days of monotonic uptime is stale whatever the wall clock says",
        )
    }

    @Test
    fun theBootCountIdentifiesTheBootNotTheClock() {
        val i = steppedBackSameBoot().copy(bootCountNow = 7, stampBootCount = 7)
        assertFalse(QuickUnlock.isFreshPure(i), "same boot count = same boot, so the monotonic delta governs")
        // And within the window, the same boot with a stepped clock is fresh on monotonic evidence.
        val short = i.copy(elapsedNowMs = 6 * day)
        assertTrue(QuickUnlock.isFreshPure(short))
        // Monotonic regression within one boot (by count) distrusts.
        assertFalse(QuickUnlock.isFreshPure(short.copy(elapsedNowMs = 4 * day)))
    }

    @Test
    fun aRealRebootStillNeedsTheServerAnchor() {
        val crossBoot = QuickUnlock.FreshnessInputs(
            nowMs = stamp + day,
            elapsedNowMs = 60_000,
            stampWallMs = stamp,
            stampElapsedMs = 5 * day,
            stampBootRefMs = stamp - 5 * day,
            highWaterWallMs = stamp + day,
            serverFloorMs = 0L,
            bootCountNow = 8,
            stampBootCount = 7,
        )
        assertFalse(QuickUnlock.isFreshPure(crossBoot), "no anchor after a reboot: password")
        assertTrue(QuickUnlock.isFreshPure(crossBoot.copy(serverFloorMs = stamp + day)))
        assertFalse(QuickUnlock.isFreshPure(crossBoot.copy(serverFloorMs = stamp + window)))
    }

    @Test
    fun aWallClockEarlierThanTheStampFailsClosed() {
        val justBefore = QuickUnlock.FreshnessInputs(
            nowMs = stamp - 20_000, // 20 s before the enrolment stamp, inside the old 5-minute skew allowance
            elapsedNowMs = 5 * day + 10_000, // and inside the boot-reference tolerance, so it read as "same boot"
            stampWallMs = stamp,
            stampElapsedMs = 5 * day,
            stampBootRefMs = stamp - 5 * day,
            highWaterWallMs = stamp,
            serverFloorMs = 0L,
        )
        assertFalse(QuickUnlock.isFreshPure(justBefore), "a clock earlier than the stamp is a rollback: password")
    }

    @Test
    fun anHonestSteadyDeviceIsUnaffected() {
        val honest = QuickUnlock.FreshnessInputs(
            nowMs = stamp + day,
            elapsedNowMs = 6 * day,
            stampWallMs = stamp,
            stampElapsedMs = 5 * day,
            stampBootRefMs = stamp - 5 * day,
            highWaterWallMs = stamp + day,
            serverFloorMs = 0L,
            bootCountNow = 3,
            stampBootCount = 3,
        )
        assertTrue(QuickUnlock.isFreshPure(honest))
    }

    // ---- q06: the restore point never moves to a pending origin ----

    @Test
    fun aSecondRepointKeepsTheFirstRestorePoint() {
        val home = "https://home.example"
        val first = PendingServer(origin = "https://hostile.example", previousOrigin = home, email = null, ts = 1)
        // store.baseUrl already points at the first, unverified origin while it is pending.
        assertEquals(home, pendingSwitchRestorePoint(existing = first, currentDefault = "https://hostile.example"))
        assertEquals(home, pendingSwitchRestorePoint(existing = null, currentDefault = home), "no pending switch: the current default IS the restore point")
        // After cancel, resolvedDefaultOrigin lands on the same restore point.
        val second = PendingServer(origin = "https://other.example", previousOrigin = pendingSwitchRestorePoint(first, "https://hostile.example"), email = null, ts = 2)
        assertEquals(home, resolvedDefaultOrigin(second, enrollSucceeded = false))
    }
}
