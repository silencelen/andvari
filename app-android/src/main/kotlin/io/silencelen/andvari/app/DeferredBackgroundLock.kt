package io.silencelen.andvari.app

/**
 * The half of G12 that never landed (audit 2026-09-13 H08).
 *
 * Lock-on-background (design 2026-08-23 §7) must never tear the engine down under an in-flight
 * op — a save, an import, a copy-to-personal, a pull-to-refresh sync — so `lockFromBackground`
 * defers when `busy` / `importBusy` / `copyOpVaultId` is set. 0.26.0 shipped that deferral as a
 * bare `return` with a comment claiming the lock "lands via getIfFresh / the next checkIdleLock
 * tick once the op completes". That is true for the IDLE lock, whose predicate (`idleExpired()`)
 * keeps being true on every later tick, and false for the BACKGROUND lock, whose trigger was a
 * one-time lifecycle event: nothing recorded that it had been requested, so a user who pressed
 * Home while a spinner was up got no lock at all — the vault sat unlocked, and autofill-servable,
 * for the whole policy window (up to 900 s), exactly the exposure the feature exists to close.
 *
 * This records the request. [defer] is called instead of the bare return; [takeIfDue] is asked
 * from the ViewModel's single in-flight-op choke point (the `_ui` collector that already mirrors
 * `busy || importBusy || copyOp` into [VaultSession]) every time that signal changes, and answers
 * true exactly once, when the op has ended AND the app is still in the background. Coming back
 * to the foreground ([returned]) cancels the request: the user is here again, the idle timer
 * stands behind them, and locking the screen they are looking at would be the wrong outcome.
 *
 * Pure state, no Android types — pinned by `DeferredBackgroundLockTest` the way
 * `theExcursionArmIsConsumedAndCleared` pins the excursion one-shot.
 */
class DeferredBackgroundLock {
    @Volatile
    private var pending = false

    /** True while the process is STARTED. Starts true: a ViewModel is created by a foreground
     *  Activity, and the first ON_STOP ([left]) is what flips it. */
    @Volatile
    private var foregrounded = true

    /** Process ON_STOP observed (whether or not the lock actually happened). */
    fun left() { foregrounded = false }

    /** Process ON_START observed: any deferred request is void — the user is back. */
    fun returned() {
        foregrounded = true
        pending = false
    }

    /** The background lock was requested under an in-flight op: remember it. */
    fun defer() { pending = true }

    /** Ask whether the deferred lock is due NOW. Consumes the request when it answers true. */
    fun takeIfDue(opInProgress: Boolean): Boolean {
        if (!pending || opInProgress || foregrounded) return false
        pending = false
        return true
    }

    /** Diagnostic read (tests) — never a decision input. */
    val isPending: Boolean get() = pending
}
