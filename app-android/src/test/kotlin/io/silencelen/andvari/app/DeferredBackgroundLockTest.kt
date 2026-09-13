package io.silencelen.andvari.app

import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Audit 2026-09-13 H08 — the G12 deferral is a DEFERRAL, not a skip. Pinned the way
 * `HealthSurfaceTest.theExcursionArmIsConsumedAndCleared` pins the excursion one-shot: the state
 * machine is pure, and the wiring (who calls what) is a source pin in HealthSurfaceTest.
 *
 * The defect: pressing Home mid-sync/save/import made `lockFromBackground` return under `busy`
 * and nothing ever re-fired the lock, so the vault stayed unlocked (and autofill-servable) for
 * the whole idle window.
 */
class DeferredBackgroundLockTest {

    /** THE BUG, fixed: backgrounded under an op → the lock fires the moment the op ends. */
    @Test
    fun aLockDeferredUnderAnOpFiresWhenTheOpEndsInTheBackground() {
        val d = DeferredBackgroundLock()
        d.left()
        d.defer()
        assertFalse(d.takeIfDue(opInProgress = true), "still busy — must not fire mid-op")
        assertTrue(d.takeIfDue(opInProgress = false), "op ended while backgrounded — fire")
        assertFalse(d.takeIfDue(opInProgress = false), "…exactly once")
    }

    /** Coming back voids the request: the user is here, the idle timer stands behind them. */
    @Test
    fun returningToTheForegroundCancelsTheDeferredLock() {
        val d = DeferredBackgroundLock()
        d.left()
        d.defer()
        d.returned(startedByOverlay = false)
        assertFalse(d.isPending)
        assertFalse(d.takeIfDue(opInProgress = false))
    }

    /** R12: ProcessLifecycleOwner's ON_START fires for ANY activity in the process — including the
     *  autofill overlays H09 ruled are not "the app". An overlay coming forward must not void the
     *  lock the user earned by leaving: the op ends, the lock still fires. */
    @Test
    fun anOverlayWakingTheProcessDoesNotVoidTheDeferredLock() {
        val d = DeferredBackgroundLock()
        d.left()
        d.defer()
        d.returned(startedByOverlay = true)
        assertTrue(d.isPending, "still requested — the user is in a browser, not back here")
        assertTrue(d.takeIfDue(opInProgress = false), "op ended while the overlay is up — fire")
    }

    /** The choke point asks on EVERY op transition — with nothing deferred, it must stay quiet. */
    @Test
    fun anOpEndingInTheForegroundNeverLocks() {
        val d = DeferredBackgroundLock()
        assertFalse(d.takeIfDue(opInProgress = false))
        d.left(); d.returned(startedByOverlay = false)
        assertFalse(d.takeIfDue(opInProgress = false))
    }

    /** A request recorded while foregrounded (impossible by construction, but cheap to pin) is
     *  not honoured until the app actually leaves. */
    @Test
    fun aRequestIsOnlyHonouredWhileBackgrounded() {
        val d = DeferredBackgroundLock()
        d.defer()
        assertFalse(d.takeIfDue(opInProgress = false), "foregrounded — not due")
        d.left()
        assertTrue(d.takeIfDue(opInProgress = false))
    }
}
