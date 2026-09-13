package io.silencelen.andvari.core.client

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeoutOrNull

/**
 * The usage recorder's stateful SHELL (spec 02 §8.2) — the buffer, the debounce, the
 * take → merge → store round trip, the swallowing session-gated catch, and the teardown
 * clear. Every RULE about the data still lives in [UsageLedger]; this owns only the moving
 * parts around it.
 *
 * WHY THIS FILE EXISTS (audit G39, the F37 pattern). Android's `UsageRecorder` object and the
 * desktop's `DesktopState` usage region each carried their own hand-copy of this ~60-line
 * shell. The two had already begun to drift in shape (the phone synchronizes across its UI +
 * autofill threads; the desktop is Main-confined and did not), and the G03 lock-path fix — a
 * BOUNDED flush that completes BEFORE the transport closes, so a lock no longer cancels the
 * GET+PUT that saves the session's last uses — had to be re-derived and re-argued on both
 * sides. Two copies of a debounce-and-network state machine guarding a leak-shaped write is
 * exactly what the F37 hoist is for. `src/jvmShared` compiles into both `jvmMain` and
 * `androidMain`, so one implementation now reaches both apps by construction; each platform
 * file is a thin adapter that supplies its session accessor and its transport.
 *
 * **Batched, never per-use** (spec 03 §3): one PUT per copy would turn the blob's own
 * `updatedAt` into a keystroke-grade activity trace, the very leak the single-blob shape exists
 * to avoid. The debounce is what keeps writes coarse; [flushWithPrune] is the one write NOT
 * driven by a use, and it is deliberately conditional (below).
 *
 * **Every failure is silent.** This is a ranking hint — it must never surface an error, block a
 * copy, or retry hard enough to be noticed.
 *
 * Thread-safety: all buffer access is `synchronized`, so the phone's UI + autofill callers are
 * safe; the desktop's Main-confined caller pays only an uncontended lock. The [scope] is the
 * platform's choice — the phone hands in its own process-wide `SupervisorJob + IO` scope; the
 * desktop hands in its Compose window scope so the flush stays Main-confined exactly as before
 * (a scope, not a bare dispatcher, so each platform keeps its own confinement).
 *
 * @param S the platform's unlocked-session type (Android's `VaultSession.Unlocked`; the
 *   desktop's captured api+account pair). [session] returns the LIVE one or null when locked;
 *   [transportFor] adapts one to the four ledger-store operations.
 */
class UsageRecorderCore<S : Any>(
    private val scope: CoroutineScope,
    private val debounceMs: Long,
    private val boundedFlushTimeoutMs: Long,
    private val session: () -> S?,
    private val transportFor: (S) -> Transport,
) {
    /** The four operations the store round trip needs, in the shape the web/extension twins
     *  read/write (the sealed form is the base64 String the `/usage` endpoint carries). */
    interface Transport {
        /** GET the current sealed usage blob; null when this account has never written one. */
        suspend fun fetchSealed(): String?
        /** Decrypt a sealed blob to its plaintext bytes (personal-VK usage key, spec 02 §8.2). */
        fun open(sealed: String): ByteArray
        /** Seal usage plaintext for storage. */
        fun seal(plain: ByteArray): String
        /** PUT the sealed blob. */
        suspend fun put(sealed: String)
    }

    private val lock = Any()
    private var pending: Map<String, UsageLedger.Entry> = emptyMap()
    private var flushJob: Job? = null

    /** Record a use. In memory only; the flush is debounced. Safe from any thread. No session
     *  → nothing to flush against, so drop it rather than buffer records with nowhere to go. */
    fun record(itemId: String, now: Long) {
        if (session() == null) return
        synchronized(lock) {
            pending = UsageLedger.record(pending, itemId, now)
            if (flushJob?.isActive == true) return
            flushJob = scope.launch {
                delay(debounceMs)
                flush()
            }
        }
    }

    /** Debounced flush against the live session. Never prunes — a debounce is not a sync, so the
     *  local view it would prune against is not provably complete (audit G04). */
    suspend fun flush() {
        val s = session() ?: return
        store(s, take(), liveItemIds = null)
    }

    /**
     * Flush against an EXPLICITLY passed session, then run [then] — the teardown path (audit
     * G03). The lock/switch caller hands its session in because it is about to drop the live
     * one, so [flush]'s own [session] lookup would already read null and the session's last
     * uses would be silently discarded. The flush is BOUNDED ([boundedFlushTimeoutMs]) and
     * [then] runs whether or not it landed — the caller hands the transport's `close()` in as
     * [then], so the GET+PUT round trip is no longer cancelled by its own teardown, yet a
     * ranking hint still can never delay the lock or hold the transport open past the bound.
     *
     * Never prunes: a teardown view can be pre-sync (locked before the first pull completed),
     * and pruning against a non-authoritative item set would drop other devices' entries
     * (audit G04). Pruning belongs to [flushWithPrune] alone.
     *
     * Returns the launched [Job] so a test can await the ORDER this exists for — [then] after the
     * bounded store — instead of polling the transport (audit H88); production callers ignore it.
     */
    fun flushForSession(explicit: S, then: () -> Unit = {}): Job {
        val mine = take()
        return scope.launch {
            if (mine.isNotEmpty()) withTimeoutOrNull(boundedFlushTimeoutMs) { store(explicit, mine, liveItemIds = null) }
            then()
        }
    }

    /**
     * Flush AND prune, against the [liveItemIds] the caller knows to be COMPLETE (audit G04).
     * The ONLY safe caller is immediately after a successful full sync, where the client has
     * pulled every envelope and `engine.liveItemIds()` is authoritative — never a
     * lock/pagehide/teardown view, which can be pre-sync. Pruning against a partial set would
     * silently discard usage for items merely not synced yet (see [UsageLedger.prune]'s
     * contract). The set must be the LIVE ENVELOPE ids, not the decrypted working set (audit
     * H36 — see [UsageLedger.liveItemIds] for why).
     *
     * Fire-and-forget on [scope] like the debounced flush — it runs after the sync coroutine, so
     * it never extends a sync. The write stays batched: [store] only PUTs when there were
     * buffered uses OR the prune actually dropped an entry, so a quiet 5-min poll that finds
     * nothing deleted costs one GET and no write (no spurious `updatedAt` bump).
     *
     * Returns the launched [Job] for the same reason as [flushForSession] (audit H88: the
     * "no write" pin must observe the flush's END, not a moment during it).
     */
    fun flushWithPrune(explicit: S, liveItemIds: Set<String>): Job {
        val mine = take()
        return scope.launch { store(explicit, mine, liveItemIds) }
    }

    /**
     * The un-flushed buffer, for DISPLAY only (design 2026-08-23). The flush is debounced by
     * design, so a user who copies a password and immediately opens Health would otherwise be
     * told that login is unused. Callers merge this over the server's copy. Returns a snapshot,
     * never the live reference, and does NOT drain (unlike [take]): reading the screen must not
     * cost the buffer its next real flush.
     */
    fun peek(): Map<String, UsageLedger.Entry> = synchronized(lock) { pending }

    private fun take(): Map<String, UsageLedger.Entry> = synchronized(lock) {
        val m = pending
        pending = emptyMap()
        m
    }

    /**
     * Read the server's current copy, decide with [UsageLedger.planFlush], then store. The re-read
     * is what keeps last-writer-wins from meaning last-writer-DESTROYS: the other devices' entries
     * survive this flush even though the endpoint has no merge semantics of its own.
     *
     * The three server outcomes are kept DISTINCT (audit H05). They used to collapse into "empty
     * server view, store ours rather than lose this session's uses" — which meant a transient GET
     * failure (5xx, timeout, rate-limit, a lock racing the token) followed by a successful PUT
     * seconds later replaced the household's whole ledger with this device's handful of buffered
     * uses, fleet-wide and unrecoverably (there is no server-side history for `usage_ledger`).
     * Spec 02 §8.2 is normative here: a client that cannot fetch or open the ledger MUST leave it
     * untouched. So on [UsageLedger.ServerCopy.Unreadable] there is no PUT; the buffer is re-armed
     * (session-gated, exactly as a failed PUT already was) and the next flush retries.
     */
    private suspend fun store(s: S, mine: Map<String, UsageLedger.Entry>, liveItemIds: Set<String>?) {
        // Nothing buffered and no prune requested → nothing to do.
        if (mine.isEmpty() && liveItemIds == null) return
        val t = transportFor(s)
        try {
            val server: UsageLedger.ServerCopy = try {
                val sealed = t.fetchSealed()
                if (sealed == null) UsageLedger.ServerCopy.Absent
                else UsageLedger.ServerCopy.Present(UsageLedger.parse(t.open(sealed).decodeToString()))
            } catch (e: CancellationException) {
                // The bounded teardown flush timing out mid-GET is a cancellation, not an
                // unreadable server: let it propagate to the outer catch, which re-arms while a
                // session stands. Swallowing it here would let the coroutine carry on into a
                // PUT on a cancelled scope.
                throw e
            } catch (_: Throwable) {
                // Offline / HTTP failure on the GET, or a present blob that would not open under
                // our key (wrong key, AD mismatch, a future encoding) — the two cases the spec's
                // MUST is about. NOT "no ledger yet": that is the null branch above.
                UsageLedger.ServerCopy.Unreadable
            }
            val put = UsageLedger.planFlush(server, mine, liveItemIds)
            if (put != null) {
                t.put(t.seal(UsageLedger.serialize(put).encodeToByteArray()))
            } else if (server is UsageLedger.ServerCopy.Unreadable) {
                // Skipped the write on purpose — keep the uses for the next round. A null plan
                // on a READABLE copy means there was simply nothing to write (quiet prune).
                rearm(mine)
            }
        } catch (_: Throwable) {
            rearm(mine)
        }
    }

    /**
     * Re-arm rather than drop — but ONLY while a session still stands. [store] resumes after
     * suspension points, so on the teardown path this can run AFTER [clear]; re-arming
     * unconditionally there would resurrect behavioural records into a locked process.
     */
    private fun rearm(mine: Map<String, UsageLedger.Entry>) {
        if (mine.isEmpty()) return
        synchronized(lock) {
            if (session() != null) pending = UsageLedger.merge(mine, pending)
        }
    }

    /** Drop the buffer and cancel the pending debounce. Called wherever vault material is
     *  dropped — behavioural records about a user's items must not outlive their session. */
    fun clear() {
        synchronized(lock) {
            flushJob?.cancel()
            flushJob = null
            pending = emptyMap()
        }
    }
}
