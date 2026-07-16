package io.silencelen.andvari.app

import android.os.SystemClock
import io.silencelen.andvari.core.client.Account
import io.silencelen.andvari.core.client.AndvariApi
import io.silencelen.andvari.core.client.ClientPolicyClamps
import io.silencelen.andvari.core.client.SyncEngine
import kotlinx.coroutines.sync.Mutex

/**
 * The B1-1 auto-lock clamp (design 2026-07-15 §2.3): `autoLockSeconds` arrives from an
 * UNAUTHENTICATED endpoint on an UNTRUSTED server, and it governs THIS device's exposure
 * window — CLIENT-FLOOR-ONLY. Effective value = clamp into `[floor, AUTO_LOCK_MAX_SECONDS]`;
 * a server-supplied 0/negative (which used to mean "never lock") clamps to the CEILING, so a
 * hostile server cannot disable auto-lock. Single source ceiling: core [ClientPolicyClamps].
 */
internal fun clampAutoLockSeconds(seconds: Int): Int =
    if (seconds <= 0) ClientPolicyClamps.AUTO_LOCK_MAX_SECONDS
    else minOf(seconds, ClientPolicyClamps.AUTO_LOCK_MAX_SECONDS)

/**
 * Process-wide holder for the unlocked vault (`AndvariApi`/`Account`/`SyncEngine`), shared
 * by the [AndvariViewModel] (main dispatcher) and the autofill service/unlock activity
 * (background). Keys are memory-only; [lock] drops everything. Nothing is persisted here.
 *
 * Thread-safety (binding requirement): [get] hands out an immutable snapshot — the
 * [Unlocked] reference itself — so a concurrent [lock] can only make a mid-flight fill
 * read slightly stale (it reads the in-memory decrypted set from the thread-safe
 * SqliteVaultCache, which survives its own `close()`), never NPE. [bind]/[lock] are
 * @Synchronized and close the previously-bound engine + api.
 *
 * Single token-holder invariant: exactly one token-carrying [AndvariApi] exists at a time
 * (the one inside the live [Unlocked]). Every api that carries tokens MUST persist
 * rotations via `SessionStore.updateTokens`; [bind] closing the previous api guarantees a
 * superseded holder cannot later reuse a consumed refresh token and revoke the device.
 */
object VaultSession {
    /**
     * A1 (quick unlock): how the CURRENT session was unlocked. [PASSWORD] means the master
     * password was actually typed THIS unlock (so a real full-password stamp exists); [QUICK]
     * means a biometric quick unlock (no password entered). Enrollment/re-enroll is gated on this
     * so a QUICK session with no surviving password stamp cannot silently reset the 30-day clock.
     */
    enum class UnlockProvenance { PASSWORD, QUICK }

    // F82: the engine's cache is no longer carried here — raw-row reads (vault rows /
    // envelopes / grants, spec 07 export + F20) go through SyncEngine's read surface.
    class Unlocked(
        val api: AndvariApi,
        val account: Account,
        val engine: SyncEngine,
        val provenance: UnlockProvenance = UnlockProvenance.PASSWORD,
    )

    @Volatile
    private var state: Unlocked? = null

    /**
     * Serializes the two unlock entry points (main-app unlock + autofill unlock). Both reuse
     * the SAME persisted refresh token; a concurrent refresh would consume it twice and trip
     * the server's reuse-detection → whole-device revocation. Holders acquire this around
     * "build api → accountKeys/refresh → bind" and re-check [get] inside so the loser reuses
     * the winner's session instead of minting a second token-holder.
     */
    val unlockMutex = Mutex()

    // ---- inactivity auto-lock (spec 01 §8: policy.autoLockSeconds) ----
    //
    // Clock choice: SystemClock.elapsedRealtime() — monotonic AND keeps counting through
    // deep sleep / doze, so a phone left in a drawer past the window is expired the moment
    // anything looks. uptimeMillis stops during sleep and would under-count idle time;
    // wall clock (currentTimeMillis) can be set backwards by the user/NTP and postpone
    // the lock indefinitely.
    @Volatile
    private var lastInteractionElapsedMs: Long = SystemClock.elapsedRealtime()

    @Volatile
    private var autoLockMs: Long = 0L // from ClientPolicy.autoLockSeconds, CLAMPED (B1-1); 0 only before first arm

    /** Record user interaction (touch/key). Called per input event — must stay this cheap. */
    fun touch() {
        lastInteractionElapsedMs = SystemClock.elapsedRealtime()
    }

    /**
     * Arm the org policy window. Callers pass the freshest value they hold — always a
     * server-derived one (a live `ClientPolicy` or its persisted per-origin mirror) — and THIS
     * single choke point applies the B1-1 clamp ([clampAutoLockSeconds]), so every arm site is
     * tighten-only by construction: a server can shorten the window, never disable or stretch
     * it past the ceiling. (Pre-clamp persisted values from old builds get re-clamped here too.)
     */
    fun setAutoLockSeconds(seconds: Int) {
        autoLockMs = clampAutoLockSeconds(seconds) * 1000L
    }

    /** True when unlocked and the inactivity window has fully elapsed. */
    fun idleExpired(): Boolean =
        state != null && autoLockMs > 0 && SystemClock.elapsedRealtime() - lastInteractionElapsedMs >= autoLockMs

    /** Seconds since the last recorded interaction — diagnostic display only
     *  (Autofill-status screen); [idleExpired]/[getIfFresh] remain the enforcement. */
    fun idleSeconds(): Long = (SystemClock.elapsedRealtime() - lastInteractionElapsedMs) / 1000

    /** The armed policy window in ms (0 = disabled) — read by the autofill hard-lock
     *  scheduler (F12) to compute its delay; [getIfFresh] remains the enforcement. */
    fun autoLockMillis(): Long = autoLockMs

    // ---- in-flight operation deferral ----
    //
    // Invariant: an idle-expiry-driven lock() must NEVER close the engine/api while a
    // mutation/import/export coroutine is running — REGARDLESS of which entry point
    // observes the expiry. AndvariViewModel.checkIdleLock() already defers on its own
    // busy/importBusy; this flag mirrors that exact signal process-wide so the OTHER
    // expiry observer ([getIfFresh], the autofill entry point) defers identically.
    // Mechanism (chosen over a begin/end counter threaded through every op): the
    // ViewModel collects its single UiState flow and publishes busy||importBusy here —
    // one choke point, no unpaired begin/end to leak. The ViewModel resets the flag to
    // false in onCleared() so a dying VM can't latch "busy" forever.
    @Volatile
    private var operationInProgress = false

    /** Published by AndvariViewModel (mirrors busy/importBusy). While true, idle-expiry
     *  observers DEFER the hard lock; the ViewModel's 1 s ticker performs it once the
     *  op completes. Manual [lock]/sign-out are unaffected. */
    fun setOperationInProgress(inProgress: Boolean) {
        operationInProgress = inProgress
    }

    /**
     * [get], but enforcing the auto-lock window first: an idle-expired vault is locked
     * (keys dropped exactly like [lock]) and null returned. This is the gate the autofill
     * entry points use, so a fill against an expired vault re-prompts for the master
     * password instead of silently serving credentials. Does NOT touch [unlockMutex]
     * (same as a manual lock): lock() closes the current token-holder, and whoever
     * unlocks next mints the new one under the mutex as usual.
     *
     * Exception — operation in progress: when the ViewModel has a mutation/import/export
     * mid-flight (see [setOperationInProgress]), the expiry does NOT hard-lock here (an
     * onFillRequest arriving while an export is writing must not yank the engine mid-op,
     * spec 07 §2.6). The still-valid session is returned for THIS fill; the deferred lock
     * lands on the ViewModel's next 1 s checkIdleLock() tick after the op finishes.
     */
    fun getIfFresh(): Unlocked? {
        if (idleExpired()) {
            if (operationInProgress) return get()
            lock()
        }
        return get()
    }

    /** Bind a freshly-unlocked session, closing any previously-bound engine/api. Provenance
     *  defaults to PASSWORD (every existing caller is a full-password unlock); the two quick-unlock
     *  callers pass QUICK explicitly (A1). */
    @Synchronized
    fun bind(
        api: AndvariApi,
        account: Account,
        engine: SyncEngine,
        provenance: UnlockProvenance = UnlockProvenance.PASSWORD,
    ) {
        touch() // spec 01 §8: the auto-lock timer resets on unlock
        val prev = state
        state = Unlocked(api, account, engine, provenance)
        prev?.let {
            if (it.engine !== engine) runCatching { it.engine.close() }
            if (it.api !== api) runCatching { it.api.close() } // never close a reused token-holder
        }
    }

    /** Immutable snapshot of the current unlocked session, or null when locked. */
    fun get(): Unlocked? = state

    /** Lock: close the engine (releasing its cache DB handle) then the api, and clear. */
    @Synchronized
    fun lock() {
        val prev = state
        state = null
        prev?.let {
            runCatching { it.engine.close() }
            runCatching { it.api.close() }
        }
    }
}
