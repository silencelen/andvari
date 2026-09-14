package io.silencelen.andvari.app

import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Audit 2026-09-13 H57 (the G64 residue) — the lock-on-background exemption EXPIRES.
 *
 * The defect: `begin()` armed a bare boolean that only a process ON_STOP (consume) or a process
 * ON_START (clear) could ever lower, and ON_START cannot fire without a preceding ON_STOP. Every
 * shipped arm but one is made immediately before a launch that stops the activity; the autofill-
 * service picker is not — on an OEM where it renders as a dialog over the still-started activity
 * no lifecycle event fires, the arm stays live, and the user's NEXT genuine backgrounding (Home,
 * app switch, screen off — possibly hours later) is silently exempted from the lock. One skipped
 * lock is the whole exposure lock-on-background exists to close, and nothing observes it.
 *
 * These run on the JVM against an INJECTED clock: [ExternalExcursion.clock] defaults to
 * `SystemClock.elapsedRealtime()`, which is not mocked under `testDebugUnitTest`, so every test
 * that touches the object must install its own clock (and put it back afterwards — the object is
 * a process singleton shared with any other test in this module).
 */
class ExternalExcursionTtlTest {

    private var now = 1_000L
    private val real = ExternalExcursion.clock

    @BeforeTest
    fun installFakeClock() {
        ExternalExcursion.clock = { now }
        ExternalExcursion.clear()
    }

    @AfterTest
    fun restoreClock() {
        ExternalExcursion.clear()
        ExternalExcursion.clock = real
    }

    /** The excursion the arm is FOR: leave, come back, the lock is skipped exactly once. */
    @Test
    fun aFreshArmStillExemptsExactlyOneBackgrounding() {
        ExternalExcursion.begin()
        now += 30_000 // a leisurely half-minute round trip through a picker
        assertTrue(ExternalExcursion.consume(), "a fresh arm must still exempt the excursion")
        assertFalse(ExternalExcursion.consume(), "…and only once")
    }

    /** THE BUG: an arm the picker never consumed must not survive to a later, unrelated leave. */
    @Test
    fun anArmOlderThanTheWindowIsStaleAndTheVaultLocks() {
        ExternalExcursion.begin()
        now += ExternalExcursion.ARM_TTL_MS + 1
        assertFalse(ExternalExcursion.consume(), "a stale arm must fail SAFE — the vault locks")
        // …and it is gone, not merely refused once: a stale arm cannot be re-tried later either.
        now = 1_000
        assertFalse(ExternalExcursion.consume(), "the stale arm must have been dropped, not kept")
    }

    /** The boundary is inclusive — a round trip that takes exactly the window is still the trip. */
    @Test
    fun theWindowBoundaryItselfIsHonoured() {
        ExternalExcursion.begin()
        now += ExternalExcursion.ARM_TTL_MS
        assertTrue(ExternalExcursion.consume(), "an arm exactly at the window is not yet stale")
    }

    /** The window is the OWNER's five minutes, not a number that drifted — a shorter one would
     *  seal the vault under a user still signing in on the site the run opened for them. */
    @Test
    fun theWindowIsFiveMinutes() {
        assertTrue(ExternalExcursion.ARM_TTL_MS == 5 * 60 * 1000L, "owner decision (H57): a five-minute arm")
    }

    /** Coming back to the foreground still drops the arm outright, window or no window. */
    @Test
    fun clearStillDropsAFreshArm() {
        ExternalExcursion.begin()
        ExternalExcursion.clear()
        assertFalse(ExternalExcursion.consume())
    }

    /** A launch that never happened (no handler, the intent threw) leaves nothing behind. */
    @Test
    fun consumeWithNoArmIsFalseAndHarmless() {
        assertFalse(ExternalExcursion.consume())
        now += ExternalExcursion.ARM_TTL_MS * 10
        assertFalse(ExternalExcursion.consume())
    }
}
