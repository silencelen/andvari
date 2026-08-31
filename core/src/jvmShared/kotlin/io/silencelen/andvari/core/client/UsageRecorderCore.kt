package io.silencelen.andvari.core.client

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
     */
    fun flushForSession(explicit: S, then: () -> Unit = {}) {
        val mine = take()
        scope.launch {
            if (mine.isNotEmpty()) withTimeoutOrNull(boundedFlushTimeoutMs) { store(explicit, mine, liveItemIds = null) }
            then()
        }
    }

    /**
     * Flush AND prune, against the [liveItemIds] the caller knows to be COMPLETE (audit G04).
     * The ONLY safe caller is immediately after a successful full sync, where the client has
     * pulled every item and `engine.items()` is authoritative — never a lock/pagehide/teardown
     * view, which can be pre-sync. Pruning against a partial set would silently discard usage
     * for items merely not synced yet (see [UsageLedger.prune]'s contract).
     *
     * Fire-and-forget on [scope] like the debounced flush — it runs after the sync coroutine, so
     * it never extends a sync. The write stays batched: [store] only PUTs when there were
     * buffered uses OR the prune actually dropped an entry, so a quiet 5-min poll that finds
     * nothing deleted costs one GET and no write (no spurious `updatedAt` bump).
     */
    fun flushWithPrune(explicit: S, liveItemIds: Set<String>) {
        val mine = take()
        scope.launch { store(explicit, mine, liveItemIds) }
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
     * Merge against the server's current copy, optionally prune, then store. The re-read is what
     * keeps last-writer-wins from meaning last-writer-DESTROYS: the other devices' entries
     * survive this flush even though the endpoint has no merge semantics of its own.
     */
    private suspend fun store(s: S, mine: Map<String, UsageLedger.Entry>, liveItemIds: Set<String>?) {
        // Nothing buffered and no prune requested → nothing to do.
        if (mine.isEmpty() && liveItemIds == null) return
        val t = transportFor(s)
        try {
            var serverCopy: Map<String, UsageLedger.Entry> = emptyMap()
            var haveServer = false
            // Could not read the remote copy — fall through with an empty server view and store
            // ours rather than lose this session's uses (the existing normal-path posture).
            runCatching {
                t.fetchSealed()?.let { sealed ->
                    serverCopy = UsageLedger.parse(t.open(sealed).decodeToString())
                    haveServer = true
                }
            }
            var merged = UsageLedger.merge(serverCopy, mine)
            // Prune (the one SHRINKING op) applies ONLY against a server copy we actually read.
            // If the remote was unreadable, pruning would drop other devices' entries we simply
            // could not see this round — so on a fetch/parse miss the prune path degrades to a
            // plain flush (store ours, drop nothing) and retries the prune on the next sync.
            // The keep-set is the live set PLUS the just-buffered uses: an item copied in the
            // sub-instant between the caller's snapshot and this flush is inherently live (you
            // can't copy a deleted item's secret), so it must not be pruned by a snapshot that
            // predates it — a stale snapshot may under-prune (retried next sync), never drop a
            // live entry.
            if (liveItemIds != null && haveServer) merged = UsageLedger.prune(merged, liveItemIds + mine.keys)
            // Skip a pointless PUT (and the `updatedAt` bump it costs) when nothing changed: no
            // buffered uses, and either no prune or a prune that dropped nothing. On the normal
            // flush path `mine` is always non-empty (empty is filtered above), so this is only
            // ever a no-op decision for the prune path.
            val changed = mine.isNotEmpty() ||
                (haveServer && merged.size != serverCopy.size) ||
                (!haveServer && merged.isNotEmpty())
            if (changed) t.put(t.seal(UsageLedger.serialize(merged).encodeToByteArray()))
        } catch (_: Throwable) {
            // Re-arm rather than drop — but ONLY while a session still stands. This resumes after
            // suspension points, so on the teardown path it can run AFTER clear(); re-arming
            // unconditionally there would resurrect behavioural records into a locked process.
            synchronized(lock) {
                if (session() != null) pending = UsageLedger.merge(mine, pending)
            }
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
