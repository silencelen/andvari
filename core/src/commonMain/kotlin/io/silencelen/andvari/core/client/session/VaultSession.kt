@file:OptIn(ExperimentalAtomicApi::class)

package io.silencelen.andvari.core.client.session

import io.silencelen.andvari.core.client.Account
import io.silencelen.andvari.core.client.AndvariApi
import io.silencelen.andvari.core.client.OriginCanon
import io.silencelen.andvari.core.client.SyncEngine
import kotlin.concurrent.Volatile
import kotlin.concurrent.atomics.AtomicBoolean
import kotlin.concurrent.atomics.ExperimentalAtomicApi
import kotlinx.atomicfu.locks.SynchronizedObject
import kotlinx.atomicfu.locks.synchronized
import kotlinx.coroutines.sync.Mutex

/**
 * What a client does as a session ends, for state the session layer does not own (Android: the
 * usage ledger's bounded teardown flush). Kept as a hook so the holder stays platform-free.
 *
 * Audit G03: the flush must get the LIVE session (state is about to drop, so a later lookup would
 * read null and the session's last uses would be silently discarded) and must finish before the
 * transport closes, or the transport's close cancels the very GET+PUT it exists to save.
 */
interface SessionEndHook {
    /**
     * Called before the session's state and keys drop, with the session still live. The
     * implementation owns [closeTransport] and MUST run it exactly once, whether or not its flush
     * landed, and bounded, so a best-effort write can never hold the transport open open-endedly.
     * The lock itself never waits for this: state and keys drop right after the call returns.
     */
    fun flush(session: VaultSession.Unlocked, closeTransport: () -> Unit)

    /** Called after state has dropped, whether or not a session was live. Behavioural records
     *  must not outlive the session that made them. */
    fun clear()

    /** No end-of-session work: the transport closes straight away. */
    object None : SessionEndHook {
        override fun flush(session: VaultSession.Unlocked, closeTransport: () -> Unit) = closeTransport()
        override fun clear() {}
    }
}

/**
 * Holder for the unlocked vault (`AndvariApi`/`Account`/`SyncEngine`), shared by a client's UI
 * layer and its background entry points (on Android, the ViewModel on the main dispatcher and the
 * autofill service/unlock activity off it). Keys are memory-only; [lock] drops everything. Nothing
 * is persisted here.
 *
 * Thread-safety (binding requirement): [get] hands out an immutable snapshot — the
 * [Unlocked] reference itself — so a concurrent [lock] can only make a mid-flight fill
 * read slightly stale (it reads the in-memory decrypted set from the thread-safe
 * SqliteVaultCache, which survives its own `close()`), never NPE. [bind]/[lock] are
 * synchronized and close the previously-bound engine + api.
 *
 * Single token-holder invariant: exactly one token-carrying [AndvariApi] exists at a time
 * (the one inside the live [Unlocked]). Every api that carries tokens MUST persist
 * rotations through the platform's session store; [bind] closing the previous api guarantees a
 * superseded holder cannot later reuse a consumed refresh token and revoke the device.
 *
 * `open` so a platform can bind one process-wide instance under a name of its own.
 */
open class VaultSession(
    private val clocks: Clocks,
    private val sessionEnd: SessionEndHook = SessionEndHook.None,
) {
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

    private val stateLock = SynchronizedObject()

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
    // Clock choice: [Clocks.monotonicMs] — monotonic AND keeps counting through deep sleep /
    // doze, so a phone left in a drawer past the window is expired the moment anything looks. A
    // clock that stops during sleep would under-count idle time; wall clock can be set backwards
    // by the user/NTP and postpone the lock indefinitely.
    @Volatile
    private var lastInteractionMs: Long = clocks.monotonicMs()

    @Volatile
    private var autoLockMs: Long = 0L // from ClientPolicy.autoLockSeconds, CLAMPED (B1-1); 0 only before first arm

    /** Record user interaction (touch/key). Called per input event — must stay this cheap. */
    fun touch() {
        lastInteractionMs = clocks.monotonicMs()
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
        state != null && autoLockMs > 0 && clocks.monotonicMs() - lastInteractionMs >= autoLockMs

    /** Seconds since the last recorded interaction — diagnostic display only
     *  (Android's Autofill-status screen); [idleExpired]/[getIfFresh] remain the enforcement. */
    fun idleSeconds(): Long = (clocks.monotonicMs() - lastInteractionMs) / 1000

    /** The armed policy window in ms (0 = disabled) — read by Android's autofill hard-lock
     *  scheduler (F12) to compute its delay; [getIfFresh] remains the enforcement. */
    fun autoLockMillis(): Long = autoLockMs

    // ---- in-flight operation deferral ----
    //
    // Invariant: an idle-expiry-driven lock() must NEVER close the engine/api while a
    // mutation/import/export coroutine is running — REGARDLESS of which entry point
    // observes the expiry. The UI layer's idle tick already defers on its own busy/importBusy;
    // this flag mirrors that exact signal process-wide so the OTHER expiry observer ([getIfFresh],
    // the autofill entry point) defers identically. Mechanism (chosen over a begin/end counter
    // threaded through every op): the UI layer publishes busy||importBusy here from its single
    // state flow — one choke point, no unpaired begin/end to leak. It resets the flag to false
    // when it is torn down, so a dying UI layer can't latch "busy" forever. Every op that
    // sets that flag runs under a whole-call bound ([runBounded]), so a server that never answers
    // cannot hold this deferral, and with it the vault, open past the policy window.
    @Volatile
    private var operationInProgress = false

    /** Published by the UI layer (mirrors busy/importBusy). While true, idle-expiry
     *  observers DEFER the hard lock; the UI layer's 1 s tick performs it once the op completes.
     *  Manual [lock]/sign-out are unaffected. */
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
     * Exception — operation in progress: when the UI layer has a mutation/import/export
     * mid-flight (see [setOperationInProgress]), the expiry does NOT hard-lock here (an
     * onFillRequest arriving while an export is writing must not yank the engine mid-op,
     * spec 07 §2.6). The still-valid session is returned for THIS fill; the deferred lock
     * lands on the UI layer's next 1 s idle check after the op finishes.
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
    fun bind(
        api: AndvariApi,
        account: Account,
        engine: SyncEngine,
        provenance: UnlockProvenance = UnlockProvenance.PASSWORD,
    ) {
        synchronized(stateLock) {
            touch() // spec 01 §8: the auto-lock timer resets on unlock
            rejected.store(false) // a new session supersedes any rejection not yet reported
            val prev = state
            state = Unlocked(api, account, engine, provenance)
            prev?.let {
                if (it.engine !== engine) runCatching { it.engine.close() }
                if (it.api !== api) runCatching { it.api.close() } // never close a reused token-holder
            }
            // The replaced engine has released its file: whatever waited on it runs now, unless the
            // new engine holds that same file open, in which case it waits on the new one instead.
            takeRunnable().forEach { runCatching { it() } }
        }
    }

    /** Immutable snapshot of the current unlocked session, or null when locked. */
    fun get(): Unlocked? = state

    /** Lock: close the engine (releasing its cache DB handle) then the api, and clear. */
    fun lock() {
        synchronized(stateLock) {
            val prev = state
            // Best-effort store of what this session recorded, BEFORE the keys go: the flush reads
            // api/account off the session, so it must be given the live one. The api teardown rides
            // the flush's completion (bounded — see [SessionEndHook.flush]): the old
            // fire-and-forget flush raced a synchronous api.close() here, which cancelled its
            // GET+PUT nearly every time and silently dropped the very records it exists to save.
            // The LOCK itself is not delayed — state and keys drop right here, the engine closes
            // right here; only this one transport's close waits, at most ~2 s.
            prev?.let { live -> sessionEnd.flush(live) { runCatching { live.api.close() } } }
            state = null
            sessionEnd.clear() // behavioural records must not outlive the session that made them
            prev?.let {
                runCatching { it.engine.close() }
            }
            takeRunnable().forEach { runCatching { it() } }
        }
    }

    // ---- a definitive rejection, for whichever UI layer is showing the session ----
    //
    // The client that hears a refused refresh is whichever one holds the session: on Android that can be
    // the autofill unlock's, for a session the main screen then adopted. Only the coordinator that heard
    // it has a callback, so the fact is kept here, process-wide, for the UI layer to find and report once.
    private val rejected = AtomicBoolean(false)

    /** Record that a definitive rejection ended the live session (set by [PolicyCoordinator]). */
    fun markRejected() = rejected.store(true)

    /** Whether the last session ended on a definitive rejection, consuming the mark so it is reported once. */
    fun takeRejected(): Boolean = rejected.exchange(false)

    // ---- durable-cache work that has to wait for the engine (spec 02 §8) ----
    //
    // Everything else a forbidding policy destroys can go immediately; the cache database cannot,
    // because the live engine holds it open and closing a database out from under a running
    // operation is the outcome the deferral above exists to prevent. So the deletion is queued
    // and runs right after the engine closes, whichever path ends the session. One entry per
    // namespace: each poll that repeats the verdict replaces the entry rather than adding one.
    private val afterEngineClose = LinkedHashMap<String, () -> Unit>() // namespace -> work; guarded by stateLock

    private fun namespace(originKey: String, userId: String) = "$originKey/$userId"

    /** The namespace whose cache file the live engine holds open, or null. Under [stateLock]. */
    private fun heldFile(): String? {
        val live = state ?: return null
        if (!live.engine.holdsDurableCache) return null
        return namespace(OriginCanon.originKey(live.api.baseUrl), live.account.userId)
    }

    /** Removes and returns the queued work no live engine is holding back. Under [stateLock]. */
    private fun takeRunnable(): List<() -> Unit> {
        val held = heldFile()
        val ready = afterEngineClose.filterKeys { it != held }
        ready.keys.forEach { afterEngineClose.remove(it) }
        return ready.values.toList()
    }

    /** Whether a live session is using this (origin, user)'s namespace. */
    fun holds(originKey: String, userId: String): Boolean {
        val live = state ?: return false
        return live.account.userId == userId && OriginCanon.originKey(live.api.baseUrl) == originKey
    }

    /**
     * Run [action] once no engine holds this (origin, user)'s cache file open: now if none does (no
     * live session there, or one running on an in-memory cache), otherwise as soon as that engine
     * closes or is replaced by one that does not hold the file. A later call for the same namespace
     * replaces the queued action, so [action] should decide from state it reads when it runs.
     */
    fun runWhenEngineCloses(originKey: String, userId: String, action: () -> Unit) {
        val queued = synchronized(stateLock) {
            val key = namespace(originKey, userId)
            val holding = heldFile() == key
            if (holding) afterEngineClose[key] = action
            holding
        }
        if (!queued) action()
    }
}
